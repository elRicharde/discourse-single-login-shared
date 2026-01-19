# name: discourse-single-login-shared
# about: Allow only one concurrent login for a specific shared user
# version: 0.6
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do
  module ::SingleLoginShared
    def self.shared_username
      (SiteSetting.single_login_shared_username || "").strip
    end

    def self.timeout_seconds
      ((SiteSetting.single_login_shared_timeout_hours || 3).to_i * 3600)
    end

    def self.shared_user?(user)
      user && user.username == shared_username
    end

    def self.lock_key(user_id)
      "single_login_shared:lock:user:#{user_id}"
    end

    def self.locked?(user_id)
      Discourse.redis.exists?(lock_key(user_id))
    end

    def self.touch_lock!(user_id)
      Discourse.redis.setex(lock_key(user_id), timeout_seconds, "1")
    end

    def self.clear_lock!(user_id)
      Discourse.redis.del(lock_key(user_id))
    end
  end

  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login = params[:login] || params[:username] || params.dig(:session, :login)
      user  = login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) && ::SingleLoginShared.locked?(user.id)
        return render_json_error(
          I18n.t("login.already_logged_in_single_session"),
          status: 403
        )
      end

      super
    ensure
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.touch_lock!(u.id)
      end
    end

    # Anmeldung bei Logout richtig löschen
    def destroy
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_lock!(u.id)
      end
      super
    end
  }

  # Anmeldung bei Admin-Logout löschen
  Admin::UsersController.prepend Module.new {
    def log_out
      user_id = params[:user_id].to_i
      u = User.find_by(id: user_id)
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_lock!(u.id)
      end
      super
    end
  }

  # Inaktivitäts-Timeout: bei jedem Request verlängern
  DiscourseEvent.on(:current_user) do |user|
    if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(user)
      ::SingleLoginShared.touch_lock!(user.id)
    end
  end
end

