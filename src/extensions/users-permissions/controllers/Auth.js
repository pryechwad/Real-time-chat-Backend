'use strict';

const { sanitizeEntity } = require('strapi-utils');

module.exports = {
  async register(ctx) {
    const pluginStore = await strapi.store({
      environment: '',
      type: 'plugin',
      name: 'users-permissions',
    });

    const settings = await pluginStore.get({ key: 'advanced' });

    if (!settings.allow_register) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.advanced.allow_register' }] }]
          : 'Register action is currently disabled.'
      );
    }

    const params = {
      ...ctx.request.body,
      provider: 'local',
    };

    // Password is required.
    if (!params.password) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.form.error.password.provide' }] }]
          : 'Please provide your password.'
      );
    }

    // Email is required.
    if (!params.email) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.form.error.email.provide' }] }]
          : 'Please provide your email.'
      );
    }

    // Check if the user exists.
    const user = await strapi.query('user', 'users-permissions').findOne({
      email: params.email.toLowerCase(),
    });

    if (user) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.form.error.email.taken' }] }]
          : 'Email is already taken.'
      );
    }

    const role = await strapi
      .query('role', 'users-permissions')
      .findOne({ type: settings.default_role }, []);

    if (!role) {
      return ctx.badRequest(
        null,
        ctx.request.admin
          ? [{ messages: [{ id: 'Auth.form.error.role.notFound' }] }]
          : 'Impossible to find the default role.'
      );
    }

    const newUser = {
      ...params,
      role: role.id,
      confirmed: settings.email_confirmation ? false : true,
    };

    const createdUser = await strapi.query('user', 'users-permissions').create(newUser);

    const sanitizedUser = sanitizeEntity(createdUser, {
      model: strapi.query('user', 'users-permissions').model,
    });

    if (settings.email_confirmation) {
      try {
        await strapi.plugins['users-permissions'].services.user.sendConfirmationEmail(sanitizedUser);
      } catch (err) {
        return ctx.badRequest(null, err);
      }

      return ctx.send({
        user: sanitizedUser,
      });
    }

    const jwt = strapi.plugins['users-permissions'].services.jwt.issue({
      id: createdUser.id,
    });

    return ctx.send({
      jwt,
      user: sanitizedUser,
    });
  },
};