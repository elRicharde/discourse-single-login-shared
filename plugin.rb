# name: discourse-single-login-shared
# about: Allow only one concurrent login for specific shared users with static max session logout
# version: 2.0
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do

  module ::SingleLoginShared
    def self.shared_usernames
      raw = (SiteSetting.single_login_shared_usernames || "").to_s
      list = raw.split(",").map { |s| s.strip }.reject(&:blank?)

      # optionaler Fallback, falls du noch irgendwo das alte Setting hattest
      if list.empty? && SiteSetting.respond_to?(:single_login_shared_username)
        old = (SiteSetting.single_login_shared_username || "").to_s.strip
        list = [old] if old.present?
      end

      list
    end

    def self.shared_user?(user)
      user && shared_usernames.include?(user.username)
    end

    def self.now
      Time.now.to_i
    end

    def self.max_session_seconds
      SiteSetting.single_login_shared_max_session_minutes.to_i * 60
    end

    # Redis keys (pro User)
    def self.active_key(user_id)
      "single_login_shared:active:user:#{user_id}"
    end

    def self.login_started_key(user_id)
      "single_login_shared:login_started:user:#{user_id}"
    end

    def self.active?(user_id)
      Discourse.redis.exists?(active_key(user_id))
    end

    def self.mark_logged_in!(user_id)
      t   = now
      ttl = max_session_seconds

      # Wenn ttl <= 0, setzen wir ohne TTL (aber Setting hat min:1, also normalerweise nie)
      if ttl > 0
        # kleine Reserve, damit es nicht exakt auf die Sekunde race-conditiont
        exp = ttl + 60
        Discourse.redis.setex(active_key(user_id), exp, "1")
        Discourse.redis.setex(login_started_key(user_id), exp, t.to_s)
      else
        Discourse.redis.set(active_key(user_id), "1")
        Discourse.redis.set(login_started_key(user_id), t.to_s)
      end
    end

    def self.clear_all!(user_id)
      Discourse.redis.del(active_key(user_id), login_started_key(user_id))
    end

    def self.force_logout!(user)
      UserAuthToken.where(user_id: user.id).find_each do |t|
        begin
          t.log_out!(SessionManager.new(nil, nil))
        rescue
        ensure
          t.destroy!
        end
      end

      clear_all!(user.id)
      ::SingleLoginShared.handle_logout_side_effects!(user, reason: "timeout")
    end

    def self.should_logout?(user_id)
      started_s = Discourse.redis.get(login_started_key(user_id))
      started   = started_s.to_i

      # Wenn active gesetzt, aber started fehlt -> inkonsistent -> logout/cleanup
      return [:inconsistent, true] if started <= 0

      ttl = max_session_seconds
      return [:ok, false] if ttl <= 0

      if (now - started) > ttl
        return [:max_session, true]
      end

      [:ok, false]
    end

    def self.enforce_timeouts!
      return unless SiteSetting.single_login_shared_enabled

      # Für alle konfigurierten Shared-User prüfen
      shared_usernames.each do |uname|
        user = User.find_by(username: uname)
        next if user.nil?

        uid = user.id
        next unless active?(uid)

        _reason, logout = should_logout?(uid)
        force_logout!(user) if logout
      end
    end

    def self.system_user_id
      Discourse.system_user&.id
    end

    def self.topic_involves_system?(topic_id)
      sid = system_user_id
      return false if sid.blank?
      TopicAllowedUser.where(topic_id: topic_id, user_id: sid).exists?
    end

    def self.topic_involves_staff_users?(topic_id)
      TopicAllowedUser
        .joins(:user)
        .where(topic_id: topic_id)
        .where("users.admin = ? OR users.moderator = ?", true, true)
        .exists?
    end

    def self.topic_involves_staff_groups?(topic_id)
      # Falls eine PN z.B. an eine Staff/Mods/Admins-Gruppe ging.
      # Discourse hat i.d.R. :staff, :admins, :moderators
      staff_group_ids = []
      [:staff, :admins, :moderators].each do |sym|
        g = Group.find_by(name: sym.to_s)
        staff_group_ids << g.id if g
      end

      return false if staff_group_ids.empty?

      TopicAllowedGroup.where(topic_id: topic_id, group_id: staff_group_ids).exists?
    end

    def self.topic_has_team_or_system?(topic_id)
      topic_involves_system?(topic_id) ||
        topic_involves_staff_users?(topic_id) ||
        topic_involves_staff_groups?(topic_id)
    end

    def self.pm_topic_ids_where_user_posted(user_id)
      Post
        .joins(:topic)
        .where(user_id: user_id)
        .where("topics.archetype = ?", Archetype.private_message)
        .distinct
        .pluck("topics.id")
    end

    def self.remove_user_from_pm_topics!(user)
      topic_ids = pm_topic_ids_where_user_posted(user.id)
      return 0 if topic_ids.blank?

      removed_topics = 0

      topic_ids.each do |tid|
        # NICHT anfassen, wenn Team oder System vorkommt
        next if topic_has_team_or_system?(tid)

        # User aus Allowed-Users entfernen -> Topic ist für ihn nicht mehr sichtbar
        deleted = TopicAllowedUser.where(topic_id: tid, user_id: user.id).delete_all

        if deleted > 0
          removed_topics += 1
          # optional housekeeping (Unreads/Tracking)
          TopicUser.where(topic_id: tid, user_id: user.id).delete_all
        end
      end

      removed_topics
    end

    def self.shared_user_has_trigger_pm?(user, title)
      return false if title.blank?

      Topic
        .joins(:topic_allowed_users)
        .where("topics.archetype = ?", Archetype.private_message)
        .where("topic_allowed_users.user_id = ?", user.id)
        .where("topics.title = ?", title)
        .exists?
    end

    def self.send_trigger_pm!(shared_user, reason: nil)
      title = (SiteSetting.single_login_shared_trigger_pm_title || "").strip
      body  = (SiteSetting.single_login_shared_trigger_pm_body  || "").to_s
      return if title.blank? || body.blank?

      # Nur senden, wenn der SharedUser keine sichtbare PM mit exakt dem Titel mehr hat
      return if shared_user_has_trigger_pm?(shared_user, title)

      sender_name = (SiteSetting.single_login_shared_sender_username || "").strip
      sender = sender_name.present? ? User.find_by(username: sender_name) : nil
      sender ||= Discourse.system_user

      group_name = (SiteSetting.single_login_shared_notify_group || "").strip
      target_group_names = []
      target_group_names << group_name if group_name.present?

      body = "#{body}\n\n(Logout-Grund: #{reason})" if reason.present?

      PostCreator.create!(
        sender,
        title: title,
        raw: body,
        archetype: Archetype.private_message,
        target_usernames: shared_user.username,
        target_group_names: target_group_names
      )
    end

    def self.handle_logout_side_effects!(user, reason: nil)
      return unless SiteSetting.single_login_shared_enabled
      return unless shared_user?(user)

      remove_user_from_pm_topics!(user)
      send_trigger_pm!(user, reason: reason)
    end    
  end

  # 1) Login blocken + nach erfolgreichem Login markieren
  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login = params[:login] || params[:username] || params.dig(:session, :login)
      user  = login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) && ::SingleLoginShared.active?(user.id)
        render json: { error: I18n.t("login.already_logged_in_single_session") }, status: 200
        return
      end

      super
    ensure
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.mark_logged_in!(u.id)
      end
    end

    # normaler Logout
    def destroy
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all!(u.id)
        ::SingleLoginShared.handle_logout_side_effects!(u, reason: "logout")
      end
      super
    end
  }

  # 2) Admin-Logout (Log out all sessions)
  Admin::UsersController.prepend Module.new {
    def log_out
      user_id = params[:user_id].to_i
      u = User.find_by(id: user_id)

      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all!(u.id)
        ::SingleLoginShared.handle_logout_side_effects!(u, reason: "admin_logout")
      end

      super
    end
  }

  # 3) Scheduled Job: erzwingt Max-Session Logout unabhängig von Requests
  module ::Jobs
    class SingleLoginSharedEnforcer < ::Jobs::Scheduled
      every 1.minute

      def execute(args)
        ::SingleLoginShared.enforce_timeouts!
      end
    end
  end
end
