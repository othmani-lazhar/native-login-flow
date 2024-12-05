create table "databasechangeloglock"
(
    "id"          integer not null
        primary key,
    "locked"      boolean not null,
    "lockgranted" timestamp,
    "lockedby"    varchar(255)
)
    /

create table "databasechangelog"
(
    "id"            varchar(255) not null,
    "author"        varchar(255) not null,
    "filename"      varchar(255) not null,
    "dateexecuted"  timestamp    not null,
    "orderexecuted" integer      not null,
    "exectype"      varchar(10)  not null,
    "md5sum"        varchar(35),
    "description"   varchar(255),
    "comments"      varchar(255),
    "tag"           varchar(255),
    "liquibase"     varchar(20),
    "contexts"      varchar(255),
    "labels"        varchar(255),
    "deployment_id" varchar(10)
)
    /

create table "client"
(
    "id"                           varchar(36)           not null
        constraint "constraint_7"
            primary key,
    "enabled"                      boolean default false not null,
    "full_scope_allowed"           boolean default false not null,
    "client_id"                    varchar(255),
    "not_before"                   integer,
    "public_client"                boolean default false not null,
    "secret"                       varchar(255),
    "base_url"                     varchar(255),
    "bearer_only"                  boolean default false not null,
    "management_url"               varchar(255),
    "surrogate_auth_required"      boolean default false not null,
    "realm_id"                     varchar(36),
    "protocol"                     varchar(255),
    "node_rereg_timeout"           integer default 0,
    "frontchannel_logout"          boolean default false not null,
    "consent_required"             boolean default false not null,
    "name"                         varchar(255),
    "service_accounts_enabled"     boolean default false not null,
    "client_authenticator_type"    varchar(255),
    "root_url"                     varchar(255),
    "description"                  varchar(255),
    "registration_token"           varchar(255),
    "standard_flow_enabled"        boolean default true  not null,
    "implicit_flow_enabled"        boolean default false not null,
    "direct_access_grants_enabled" boolean default false not null,
    "always_display_in_console"    boolean default false not null,
    constraint "uk_b71cjlbenv945rb6gcon438at"
        unique ("realm_id", "client_id")
)
    /

create index "idx_client_id"
    on "client" ("client_id")
    /

create table "event_entity"
(
    "id"                      varchar(36) not null
        constraint "constraint_4"
            primary key,
    "client_id"               varchar(255),
    "details_json"            varchar(2550),
    "error"                   varchar(255),
    "ip_address"              varchar(255),
    "realm_id"                varchar(255),
    "session_id"              varchar(255),
    "event_time"              bigint,
    "type"                    varchar(255),
    "user_id"                 varchar(255),
    "details_json_long_value" text
)
    /

create index "idx_event_time"
    on "event_entity" ("realm_id", "event_time")
    /

create table "realm"
(
    "id"                           varchar(36)               not null
        constraint "constraint_4a"
            primary key,
    "access_code_lifespan"         integer,
    "user_action_lifespan"         integer,
    "access_token_lifespan"        integer,
    "account_theme"                varchar(255),
    "admin_theme"                  varchar(255),
    "email_theme"                  varchar(255),
    "enabled"                      boolean     default false not null,
    "events_enabled"               boolean     default false not null,
    "events_expiration"            bigint,
    "login_theme"                  varchar(255),
    "name"                         varchar(255)
        constraint "uk_orvsdmla56612eaefiq6wl5oi"
            unique,
    "not_before"                   integer,
    "password_policy"              varchar(2550),
    "registration_allowed"         boolean     default false not null,
    "remember_me"                  boolean     default false not null,
    "reset_password_allowed"       boolean     default false not null,
    "social"                       boolean     default false not null,
    "ssl_required"                 varchar(255),
    "sso_idle_timeout"             integer,
    "sso_max_lifespan"             integer,
    "update_profile_on_soc_login"  boolean     default false not null,
    "verify_email"                 boolean     default false not null,
    "master_admin_client"          varchar(36),
    "login_lifespan"               integer,
    "internationalization_enabled" boolean     default false not null,
    "default_locale"               varchar(255),
    "reg_email_as_username"        boolean     default false not null,
    "admin_events_enabled"         boolean     default false not null,
    "admin_events_details_enabled" boolean     default false not null,
    "edit_username_allowed"        boolean     default false not null,
    "otp_policy_counter"           integer     default 0,
    "otp_policy_window"            integer     default 1,
    "otp_policy_period"            integer     default 30,
    "otp_policy_digits"            integer     default 6,
    "otp_policy_alg"               varchar(36) default 'HmacSHA1'::character varying,
    "otp_policy_type"              varchar(36) default 'totp'::character varying,
    "browser_flow"                 varchar(36),
    "registration_flow"            varchar(36),
    "direct_grant_flow"            varchar(36),
    "reset_credentials_flow"       varchar(36),
    "client_auth_flow"             varchar(36),
    "offline_session_idle_timeout" integer     default 0,
    "revoke_refresh_token"         boolean     default false not null,
    "access_token_life_implicit"   integer     default 0,
    "login_with_email_allowed"     boolean     default true  not null,
    "duplicate_emails_allowed"     boolean     default false not null,
    "docker_auth_flow"             varchar(36),
    "refresh_token_max_reuse"      integer     default 0,
    "allow_user_managed_access"    boolean     default false not null,
    "sso_max_lifespan_remember_me" integer     default 0     not null,
    "sso_idle_timeout_remember_me" integer     default 0     not null,
    "default_role"                 varchar(255)
)
    /

create table "keycloak_role"
(
    "id"                      varchar(36)           not null
        constraint "constraint_a"
            primary key,
    "client_realm_constraint" varchar(255),
    "client_role"             boolean default false not null,
    "description"             varchar(255),
    "name"                    varchar(255),
    "realm_id"                varchar(255),
    "client"                  varchar(36),
    "realm"                   varchar(36)
        constraint "fk_6vyqfe4cn4wlq8r6kt5vdsj5c"
            references "realm",
    constraint "UK_J3RWUVD56ONTGSUHOGM184WW2-2"
        unique ("name", "client_realm_constraint")
)
    /

create table "composite_role"
(
    "composite"  varchar(36) not null
        constraint "fk_a63wvekftu8jo1pnj81e7mce2"
            references "keycloak_role",
    "child_role" varchar(36) not null
        constraint "fk_gr7thllb9lu8q4vqa4524jjy8"
            references "keycloak_role",
    constraint "constraint_composite_role"
        primary key ("composite", "child_role")
)
    /

create index "idx_composite"
    on "composite_role" ("composite")
    /

create index "idx_composite_child"
    on "composite_role" ("child_role")
    /

create index "idx_keycloak_role_client"
    on "keycloak_role" ("client")
    /

create index "idx_keycloak_role_realm"
    on "keycloak_role" ("realm")
    /

create index "idx_realm_master_adm_cli"
    on "realm" ("master_admin_client")
    /

create table "realm_attribute"
(
    "name"     varchar(255) not null,
    "realm_id" varchar(36)  not null
        constraint "fk_8shxd6l3e9atqukacxgpffptw"
            references "realm",
    "value"    text,
    constraint "constraint_9"
        primary key ("name", "realm_id")
)
    /

create index "idx_realm_attr_realm"
    on "realm_attribute" ("realm_id")
    /

create table "realm_events_listeners"
(
    "realm_id" varchar(36)  not null
        constraint "fk_h846o4h0w8epx5nxev9f5y69j"
            references "realm",
    "value"    varchar(255) not null,
    constraint "constr_realm_events_listeners"
        primary key ("realm_id", "value")
)
    /

create index "idx_realm_evt_list_realm"
    on "realm_events_listeners" ("realm_id")
    /

create table "realm_required_credential"
(
    "type"       varchar(255)          not null,
    "form_label" varchar(255),
    "input"      boolean default false not null,
    "secret"     boolean default false not null,
    "realm_id"   varchar(36)           not null
        constraint "fk_5hg65lybevavkqfki3kponh9v"
            references "realm",
    constraint "constraint_92"
        primary key ("realm_id", "type")
)
    /

create table "realm_smtp_config"
(
    "realm_id" varchar(36)  not null
        constraint "fk_70ej8xdxgxd0b9hh6180irr0o"
            references "realm",
    "value"    varchar(255),
    "name"     varchar(255) not null,
    constraint "constraint_e"
        primary key ("realm_id", "name")
)
    /

create table "redirect_uris"
(
    "client_id" varchar(36)  not null
        constraint "fk_1burs8pb4ouj97h5wuppahv9f"
            references "client",
    "value"     varchar(255) not null,
    constraint "constraint_redirect_uris"
        primary key ("client_id", "value")
)
    /

create index "idx_redir_uri_client"
    on "redirect_uris" ("client_id")
    /

create table "scope_mapping"
(
    "client_id" varchar(36) not null
        constraint "fk_ouse064plmlr732lxjcn1q5f1"
            references "client",
    "role_id"   varchar(36) not null,
    constraint "constraint_81"
        primary key ("client_id", "role_id")
)
    /

create index "idx_scope_mapping_role"
    on "scope_mapping" ("role_id")
    /

create table "username_login_failure"
(
    "realm_id"                varchar(36)  not null,
    "username"                varchar(255) not null,
    "failed_login_not_before" integer,
    "last_failure"            bigint,
    "last_ip_failure"         varchar(255),
    "num_failures"            integer,
    constraint "CONSTRAINT_17-2"
        primary key ("realm_id", "username")
)
    /

create table "user_entity"
(
    "id"                          varchar(36)           not null
        constraint "constraint_fb"
            primary key,
    "email"                       varchar(255),
    "email_constraint"            varchar(255),
    "email_verified"              boolean default false not null,
    "enabled"                     boolean default false not null,
    "federation_link"             varchar(255),
    "first_name"                  varchar(255),
    "last_name"                   varchar(255),
    "realm_id"                    varchar(255),
    "username"                    varchar(255),
    "created_timestamp"           bigint,
    "service_account_client_link" varchar(255),
    "not_before"                  integer default 0     not null,
    constraint "uk_dykn684sl8up1crfei6eckhd7"
        unique ("realm_id", "email_constraint"),
    constraint "uk_ru8tt6t700s9v50bu18ws5ha6"
        unique ("realm_id", "username")
)
    /

create table "credential"
(
    "id"              varchar(36) not null
        constraint "constraint_f"
            primary key,
    "salt"            bytea,
    "type"            varchar(255),
    "user_id"         varchar(36)
        constraint "fk_pfyr0glasqyl0dei3kl69r6v0"
            references "user_entity",
    "created_date"    bigint,
    "user_label"      varchar(255),
    "secret_data"     text,
    "credential_data" text,
    "priority"        integer
)
    /

create index "idx_user_credential"
    on "credential" ("user_id")
    /

create table "user_attribute"
(
    "name"                       varchar(255) not null,
    "value"                      varchar(255),
    "user_id"                    varchar(36)  not null
        constraint "fk_5hrm2vlf9ql5fu043kqepovbr"
            references "user_entity",
    "id"                         varchar(36) default 'sybase-needs-something-here'::character varying not null
		constraint "constraint_user_attribute_pk"
			primary key,
    "long_value_hash"            bytea,
    "long_value_hash_lower_case" bytea,
    "long_value"                 text
)
    /

create index "idx_user_attribute"
    on "user_attribute" ("user_id")
    /

create index "idx_user_attribute_name"
    on "user_attribute" ("name", "value")
    /

create index "user_attr_long_values"
    on "user_attribute" ("long_value_hash", "name")
    /

create index "user_attr_long_values_lower_case"
    on "user_attribute" ("long_value_hash_lower_case", "name")
    /

create index "idx_user_email"
    on "user_entity" ("email")
    /

create index "idx_user_service_account"
    on "user_entity" ("realm_id", "service_account_client_link")
    /

create table "user_federation_provider"
(
    "id"                  varchar(36) not null
        constraint "constraint_5c"
            primary key,
    "changed_sync_period" integer,
    "display_name"        varchar(255),
    "full_sync_period"    integer,
    "last_sync"           integer,
    "priority"            integer,
    "provider_name"       varchar(255),
    "realm_id"            varchar(36)
        constraint "fk_1fj32f6ptolw2qy60cd8n01e8"
            references "realm"
)
    /

create table "user_federation_config"
(
    "user_federation_provider_id" varchar(36)  not null
        constraint "fk_t13hpu1j94r2ebpekr39x5eu5"
            references "user_federation_provider",
    "value"                       varchar(255),
    "name"                        varchar(255) not null,
    constraint "constraint_f9"
        primary key ("user_federation_provider_id", "name")
)
    /

create index "idx_usr_fed_prv_realm"
    on "user_federation_provider" ("realm_id")
    /

create table "user_required_action"
(
    "user_id"         varchar(36) not null
        constraint "fk_6qj3w1jw9cvafhe19bwsiuvmd"
            references "user_entity",
    "required_action" varchar(255) default ' '::character varying not null,
    constraint "constraint_required_action"
        primary key ("required_action", "user_id")
)
    /

create index "idx_user_reqactions"
    on "user_required_action" ("user_id")
    /

create table "user_role_mapping"
(
    "role_id" varchar(255) not null,
    "user_id" varchar(36)  not null
        constraint "fk_c4fqv34p1mbylloxang7b1q3l"
            references "user_entity",
    constraint "constraint_c"
        primary key ("role_id", "user_id")
)
    /

create index "idx_user_role_mapping"
    on "user_role_mapping" ("user_id")
    /

create table "web_origins"
(
    "client_id" varchar(36)  not null
        constraint "fk_lojpho213xcx4wnkog82ssrfy"
            references "client",
    "value"     varchar(255) not null,
    constraint "constraint_web_origins"
        primary key ("client_id", "value")
)
    /

create index "idx_web_orig_client"
    on "web_origins" ("client_id")
    /

create table "client_attributes"
(
    "client_id" varchar(36)  not null
        constraint "fk3c47c64beacca966"
            references "client",
    "name"      varchar(255) not null,
    "value"     text,
    constraint "constraint_3c"
        primary key ("client_id", "name")
)
    /

create index "idx_client_att_by_name_value"
    on "client_attributes" ("name", substr(value, 1, 255))
    /

create table "client_node_registrations"
(
    "client_id" varchar(36)  not null
        constraint "fk4129723ba992f594"
            references "client",
    "value"     integer,
    "name"      varchar(255) not null,
    constraint "constraint_84"
        primary key ("client_id", "name")
)
    /

create table "federated_identity"
(
    "identity_provider"  varchar(255) not null,
    "realm_id"           varchar(36),
    "federated_user_id"  varchar(255),
    "federated_username" varchar(255),
    "token"              text,
    "user_id"            varchar(36)  not null
        constraint "fk404288b92ef007a6"
            references "user_entity",
    constraint "constraint_40"
        primary key ("identity_provider", "user_id")
)
    /

create index "idx_fedidentity_user"
    on "federated_identity" ("user_id")
    /

create index "idx_fedidentity_feduser"
    on "federated_identity" ("federated_user_id")
    /

create table "identity_provider"
(
    "internal_id"                varchar(36)           not null
        constraint "constraint_2b"
            primary key,
    "enabled"                    boolean default false not null,
    "provider_alias"             varchar(255),
    "provider_id"                varchar(255),
    "store_token"                boolean default false not null,
    "authenticate_by_default"    boolean default false not null,
    "realm_id"                   varchar(36)
        constraint "fk2b4ebc52ae5c3b34"
            references "realm",
    "add_token_role"             boolean default true  not null,
    "trust_email"                boolean default false not null,
    "first_broker_login_flow_id" varchar(36),
    "post_broker_login_flow_id"  varchar(36),
    "provider_display_name"      varchar(255),
    "link_only"                  boolean default false not null,
    "organization_id"            varchar(255),
    "hide_on_login"              boolean default false,
    constraint "uk_2daelwnibji49avxsrtuf6xj33"
        unique ("provider_alias", "realm_id")
)
    /

create index "idx_ident_prov_realm"
    on "identity_provider" ("realm_id")
    /

create index "idx_idp_realm_org"
    on "identity_provider" ("realm_id", "organization_id")
    /

create index "idx_idp_for_login"
    on "identity_provider" ("realm_id", "enabled", "link_only", "hide_on_login", "organization_id")
    /

create table "identity_provider_config"
(
    "identity_provider_id" varchar(36)  not null
        constraint "fkdc4897cf864c4e43"
            references "identity_provider",
    "value"                text,
    "name"                 varchar(255) not null,
    constraint "constraint_d"
        primary key ("identity_provider_id", "name")
)
    /

create table "realm_supported_locales"
(
    "realm_id" varchar(36)  not null
        constraint "fk_supported_locales_realm"
            references "realm",
    "value"    varchar(255) not null,
    constraint "constr_realm_supported_locales"
        primary key ("realm_id", "value")
)
    /

create index "idx_realm_supp_local_realm"
    on "realm_supported_locales" ("realm_id")
    /

create table "realm_enabled_event_types"
(
    "realm_id" varchar(36)  not null
        constraint "fk_h846o4h0w8epx5nwedrf5y69j"
            references "realm",
    "value"    varchar(255) not null,
    constraint "constr_realm_enabl_event_types"
        primary key ("realm_id", "value")
)
    /

create index "idx_realm_evt_types_realm"
    on "realm_enabled_event_types" ("realm_id")
    /

create table "migration_model"
(
    "id"          varchar(36)      not null
        constraint "constraint_migmod"
            primary key,
    "version"     varchar(36),
    "update_time" bigint default 0 not null
)
    /

create index "idx_update_time"
    on "migration_model" ("update_time")
    /

create table "identity_provider_mapper"
(
    "id"              varchar(36)  not null
        constraint "constraint_idpm"
            primary key,
    "name"            varchar(255) not null,
    "idp_alias"       varchar(255) not null,
    "idp_mapper_name" varchar(255) not null,
    "realm_id"        varchar(36)  not null
        constraint "fk_idpm_realm"
            references "realm"
)
    /

create index "idx_id_prov_mapp_realm"
    on "identity_provider_mapper" ("realm_id")
    /

create table "idp_mapper_config"
(
    "idp_mapper_id" varchar(36)  not null
        constraint "fk_idpmconfig"
            references "identity_provider_mapper",
    "value"         text,
    "name"          varchar(255) not null,
    constraint "constraint_idpmconfig"
        primary key ("idp_mapper_id", "name")
)
    /

create table "user_consent"
(
    "id"                      varchar(36) not null
        constraint "constraint_grntcsnt_pm"
            primary key,
    "client_id"               varchar(255),
    "user_id"                 varchar(36) not null
        constraint "fk_grntcsnt_user"
            references "user_entity",
    "created_date"            bigint,
    "last_updated_date"       bigint,
    "client_storage_provider" varchar(36),
    "external_client_id"      varchar(255),
    constraint "uk_local_consent"
        unique ("client_id", "user_id"),
    constraint "uk_external_consent"
        unique ("client_storage_provider", "external_client_id", "user_id")
)
    /

create index "idx_user_consent"
    on "user_consent" ("user_id")
    /

create table "admin_event_entity"
(
    "id"               varchar(36) not null
        constraint "constraint_admin_event_entity"
            primary key,
    "admin_event_time" bigint,
    "realm_id"         varchar(255),
    "operation_type"   varchar(255),
    "auth_realm_id"    varchar(255),
    "auth_client_id"   varchar(255),
    "auth_user_id"     varchar(255),
    "ip_address"       varchar(255),
    "resource_path"    varchar(2550),
    "representation"   text,
    "error"            varchar(255),
    "resource_type"    varchar(64)
)
    /

create index "idx_admin_event_time"
    on "admin_event_entity" ("realm_id", "admin_event_time")
    /

create table "authenticator_config"
(
    "id"       varchar(36) not null
        constraint "constraint_auth_pk"
            primary key,
    "alias"    varchar(255),
    "realm_id" varchar(36)
        constraint "fk_auth_realm"
            references "realm"
)
    /

create index "idx_auth_config_realm"
    on "authenticator_config" ("realm_id")
    /

create table "authentication_flow"
(
    "id"          varchar(36)               not null
        constraint "constraint_auth_flow_pk"
            primary key,
    "alias"       varchar(255),
    "description" varchar(255),
    "realm_id"    varchar(36)
        constraint "fk_auth_flow_realm"
            references "realm",
    "provider_id" varchar(36) default 'basic-flow'::character varying not null,
    "top_level"   boolean     default false not null,
    "built_in"    boolean     default false not null
)
    /

create index "idx_auth_flow_realm"
    on "authentication_flow" ("realm_id")
    /

create table "authentication_execution"
(
    "id"                 varchar(36)           not null
        constraint "constraint_auth_exec_pk"
            primary key,
    "alias"              varchar(255),
    "authenticator"      varchar(36),
    "realm_id"           varchar(36)
        constraint "fk_auth_exec_realm"
            references "realm",
    "flow_id"            varchar(36)
        constraint "fk_auth_exec_flow"
            references "authentication_flow",
    "requirement"        integer,
    "priority"           integer,
    "authenticator_flow" boolean default false not null,
    "auth_flow_id"       varchar(36),
    "auth_config"        varchar(36)
)
    /

create index "idx_auth_exec_realm_flow"
    on "authentication_execution" ("realm_id", "flow_id")
    /

create index "idx_auth_exec_flow"
    on "authentication_execution" ("flow_id")
    /

create table "authenticator_config_entry"
(
    "authenticator_id" varchar(36)  not null,
    "value"            text,
    "name"             varchar(255) not null,
    constraint "constraint_auth_cfg_pk"
        primary key ("authenticator_id", "name")
)
    /

create table "user_federation_mapper"
(
    "id"                     varchar(36)  not null
        constraint "constraint_fedmapperpm"
            primary key,
    "name"                   varchar(255) not null,
    "federation_provider_id" varchar(36)  not null
        constraint "fk_fedmapperpm_fedprv"
            references "user_federation_provider",
    "federation_mapper_type" varchar(255) not null,
    "realm_id"               varchar(36)  not null
        constraint "fk_fedmapperpm_realm"
            references "realm"
)
    /

create index "idx_usr_fed_map_fed_prv"
    on "user_federation_mapper" ("federation_provider_id")
    /

create index "idx_usr_fed_map_realm"
    on "user_federation_mapper" ("realm_id")
    /

create table "user_federation_mapper_config"
(
    "user_federation_mapper_id" varchar(36)  not null
        constraint "fk_fedmapper_cfg"
            references "user_federation_mapper",
    "value"                     varchar(255),
    "name"                      varchar(255) not null,
    constraint "constraint_fedmapper_cfg_pm"
        primary key ("user_federation_mapper_id", "name")
)
    /

create table "required_action_provider"
(
    "id"             varchar(36)           not null
        constraint "constraint_req_act_prv_pk"
            primary key,
    "alias"          varchar(255),
    "name"           varchar(255),
    "realm_id"       varchar(36)
        constraint "fk_req_act_realm"
            references "realm",
    "enabled"        boolean default false not null,
    "default_action" boolean default false not null,
    "provider_id"    varchar(255),
    "priority"       integer
)
    /

create index "idx_req_act_prov_realm"
    on "required_action_provider" ("realm_id")
    /

create table "required_action_config"
(
    "required_action_id" varchar(36)  not null,
    "value"              text,
    "name"               varchar(255) not null,
    constraint "constraint_req_act_cfg_pk"
        primary key ("required_action_id", "name")
)
    /

create table "offline_user_session"
(
    "user_session_id"      varchar(36)       not null,
    "user_id"              varchar(255)      not null,
    "realm_id"             varchar(36)       not null,
    "created_on"           integer           not null,
    "offline_flag"         varchar(4)        not null,
    "data"                 text,
    "last_session_refresh" integer default 0 not null,
    "broker_session_id"    varchar(1024),
    "version"              integer default 0,
    constraint "constraint_offl_us_ses_pk2"
        primary key ("user_session_id", "offline_flag")
)
    /

create index "idx_offline_uss_by_user"
    on "offline_user_session" ("user_id", "realm_id", "offline_flag")
    /

create index "idx_offline_uss_by_last_session_refresh"
    on "offline_user_session" ("realm_id", "offline_flag", "last_session_refresh")
    /

create index "idx_offline_uss_by_broker_session_id"
    on "offline_user_session" ("broker_session_id", "realm_id")
    /

create table "offline_client_session"
(
    "user_session_id"         varchar(36)  not null,
    "client_id"               varchar(255) not null,
    "offline_flag"            varchar(4)   not null,
    "timestamp"               integer,
    "data"                    text,
    "client_storage_provider" varchar(36)  default 'local'::character varying not null,
    "external_client_id"      varchar(255) default 'local'::character varying not null,
    "version"                 integer      default 0,
    constraint "constraint_offl_cl_ses_pk3"
        primary key ("user_session_id", "client_id", "client_storage_provider", "external_client_id", "offline_flag")
)
    /

create table "keycloak_group"
(
    "id"           varchar(36)       not null
        constraint "constraint_group"
            primary key,
    "name"         varchar(255),
    "parent_group" varchar(36)       not null,
    "realm_id"     varchar(36),
    "type"         integer default 0 not null,
    constraint "sibling_names"
        unique ("realm_id", "parent_group", "name")
)
    /

create table "group_role_mapping"
(
    "role_id"  varchar(36) not null,
    "group_id" varchar(36) not null
        constraint "fk_group_role_group"
            references "keycloak_group",
    constraint "constraint_group_role"
        primary key ("role_id", "group_id")
)
    /

create index "idx_group_role_mapp_group"
    on "group_role_mapping" ("group_id")
    /

create table "group_attribute"
(
    "id"       varchar(36) default 'sybase-needs-something-here'::character varying not null
		constraint "constraint_group_attribute_pk"
			primary key,
    "name"     varchar(255) not null,
    "value"    varchar(255),
    "group_id" varchar(36)  not null
        constraint "fk_group_attribute_group"
            references "keycloak_group"
)
    /

create index "idx_group_attr_group"
    on "group_attribute" ("group_id")
    /

create index "idx_group_att_by_name_value"
    on "group_attribute" ("name", (value::character varying(250)))
    /

create table "user_group_membership"
(
    "group_id"        varchar(36)  not null,
    "user_id"         varchar(36)  not null
        constraint "fk_user_group_user"
            references "user_entity",
    "membership_type" varchar(255) not null,
    constraint "constraint_user_group"
        primary key ("group_id", "user_id")
)
    /

create index "idx_user_group_mapping"
    on "user_group_membership" ("user_id")
    /

create table "realm_default_groups"
(
    "realm_id" varchar(36) not null
        constraint "fk_def_groups_realm"
            references "realm",
    "group_id" varchar(36) not null
        constraint "con_group_id_def_groups"
            unique,
    constraint "constr_realm_default_groups"
        primary key ("realm_id", "group_id")
)
    /

create index "idx_realm_def_grp_realm"
    on "realm_default_groups" ("realm_id")
    /

create table "client_scope"
(
    "id"          varchar(36) not null
        constraint "pk_cli_template"
            primary key,
    "name"        varchar(255),
    "realm_id"    varchar(36),
    "description" varchar(255),
    "protocol"    varchar(255),
    constraint "uk_cli_scope"
        unique ("realm_id", "name")
)
    /

create table "protocol_mapper"
(
    "id"                   varchar(36)  not null
        constraint "constraint_pcm"
            primary key,
    "name"                 varchar(255) not null,
    "protocol"             varchar(255) not null,
    "protocol_mapper_name" varchar(255) not null,
    "client_id"            varchar(36)
        constraint "fk_pcm_realm"
            references "client",
    "client_scope_id"      varchar(36)
        constraint "fk_cli_scope_mapper"
            references "client_scope"
)
    /

create index "idx_protocol_mapper_client"
    on "protocol_mapper" ("client_id")
    /

create index "idx_clscope_protmap"
    on "protocol_mapper" ("client_scope_id")
    /

create table "protocol_mapper_config"
(
    "protocol_mapper_id" varchar(36)  not null
        constraint "fk_pmconfig"
            references "protocol_mapper",
    "value"              text,
    "name"               varchar(255) not null,
    constraint "constraint_pmconfig"
        primary key ("protocol_mapper_id", "name")
)
    /

create index "idx_realm_clscope"
    on "client_scope" ("realm_id")
    /

create table "client_scope_attributes"
(
    "scope_id" varchar(36)  not null
        constraint "fk_cl_scope_attr_scope"
            references "client_scope",
    "value"    varchar(2048),
    "name"     varchar(255) not null,
    constraint "pk_cl_tmpl_attr"
        primary key ("scope_id", "name")
)
    /

create index "idx_clscope_attrs"
    on "client_scope_attributes" ("scope_id")
    /

create table "client_scope_role_mapping"
(
    "scope_id" varchar(36) not null
        constraint "fk_cl_scope_rm_scope"
            references "client_scope",
    "role_id"  varchar(36) not null,
    constraint "pk_template_scope"
        primary key ("scope_id", "role_id")
)
    /

create index "idx_clscope_role"
    on "client_scope_role_mapping" ("scope_id")
    /

create index "idx_role_clscope"
    on "client_scope_role_mapping" ("role_id")
    /

create table "resource_server"
(
    "id"                   varchar(36)            not null
        constraint "pk_resource_server"
            primary key,
    "allow_rs_remote_mgmt" boolean  default false not null,
    "policy_enforce_mode"  smallint               not null,
    "decision_strategy"    smallint default 1     not null
)
    /

create table "resource_server_resource"
(
    "id"                   varchar(36)           not null
        constraint "constraint_farsr"
            primary key,
    "name"                 varchar(255)          not null,
    "type"                 varchar(255),
    "icon_uri"             varchar(255),
    "owner"                varchar(255)          not null,
    "resource_server_id"   varchar(36)           not null
        constraint "fk_frsrho213xcx4wnkog82ssrfy"
            references "resource_server",
    "owner_managed_access" boolean default false not null,
    "display_name"         varchar(255),
    constraint "uk_frsr6t700s9v50bu18ws5ha6"
        unique ("name", "owner", "resource_server_id")
)
    /

create index "idx_res_srv_res_res_srv"
    on "resource_server_resource" ("resource_server_id")
    /

create table "resource_server_scope"
(
    "id"                 varchar(36)  not null
        constraint "constraint_farsrs"
            primary key,
    "name"               varchar(255) not null,
    "icon_uri"           varchar(255),
    "resource_server_id" varchar(36)  not null
        constraint "fk_frsrso213xcx4wnkog82ssrfy"
            references "resource_server",
    "display_name"       varchar(255),
    constraint "uk_frsrst700s9v50bu18ws5ha6"
        unique ("name", "resource_server_id")
)
    /

create index "idx_res_srv_scope_res_srv"
    on "resource_server_scope" ("resource_server_id")
    /

create table "resource_server_policy"
(
    "id"                 varchar(36)  not null
        constraint "constraint_farsrp"
            primary key,
    "name"               varchar(255) not null,
    "description"        varchar(255),
    "type"               varchar(255) not null,
    "decision_strategy"  smallint,
    "logic"              smallint,
    "resource_server_id" varchar(36)  not null
        constraint "fk_frsrpo213xcx4wnkog82ssrfy"
            references "resource_server",
    "owner"              varchar(255),
    constraint "uk_frsrpt700s9v50bu18ws5ha6"
        unique ("name", "resource_server_id")
)
    /

create index "idx_res_serv_pol_res_serv"
    on "resource_server_policy" ("resource_server_id")
    /

create table "policy_config"
(
    "policy_id" varchar(36)  not null
        constraint "fkdc34197cf864c4e43"
            references "resource_server_policy",
    "name"      varchar(255) not null,
    "value"     text,
    constraint "constraint_dpc"
        primary key ("policy_id", "name")
)
    /

create table "resource_scope"
(
    "resource_id" varchar(36) not null
        constraint "fk_frsrpos13xcx4wnkog82ssrfy"
            references "resource_server_resource",
    "scope_id"    varchar(36) not null
        constraint "fk_frsrps213xcx4wnkog82ssrfy"
            references "resource_server_scope",
    constraint "constraint_farsrsp"
        primary key ("resource_id", "scope_id")
)
    /

create index "idx_res_scope_scope"
    on "resource_scope" ("scope_id")
    /

create table "resource_policy"
(
    "resource_id" varchar(36) not null
        constraint "fk_frsrpos53xcx4wnkog82ssrfy"
            references "resource_server_resource",
    "policy_id"   varchar(36) not null
        constraint "fk_frsrpp213xcx4wnkog82ssrfy"
            references "resource_server_policy",
    constraint "constraint_farsrpp"
        primary key ("resource_id", "policy_id")
)
    /

create index "idx_res_policy_policy"
    on "resource_policy" ("policy_id")
    /

create table "scope_policy"
(
    "scope_id"  varchar(36) not null
        constraint "fk_frsrpass3xcx4wnkog82ssrfy"
            references "resource_server_scope",
    "policy_id" varchar(36) not null
        constraint "fk_frsrasp13xcx4wnkog82ssrfy"
            references "resource_server_policy",
    constraint "constraint_farsrsps"
        primary key ("scope_id", "policy_id")
)
    /

create index "idx_scope_policy_policy"
    on "scope_policy" ("policy_id")
    /

create table "associated_policy"
(
    "policy_id"            varchar(36) not null
        constraint "fk_frsrpas14xcx4wnkog82ssrfy"
            references "resource_server_policy",
    "associated_policy_id" varchar(36) not null
        constraint "fk_frsr5s213xcx4wnkog82ssrfy"
            references "resource_server_policy",
    constraint "constraint_farsrpap"
        primary key ("policy_id", "associated_policy_id")
)
    /

create index "idx_assoc_pol_assoc_pol_id"
    on "associated_policy" ("associated_policy_id")
    /

create table "broker_link"
(
    "identity_provider"   varchar(255) not null,
    "storage_provider_id" varchar(255),
    "realm_id"            varchar(36)  not null,
    "broker_user_id"      varchar(255),
    "broker_username"     varchar(255),
    "token"               text,
    "user_id"             varchar(255) not null,
    constraint "constr_broker_link_pk"
        primary key ("identity_provider", "user_id")
)
    /

create table "fed_user_attribute"
(
    "id"                         varchar(36)  not null
        constraint "constr_fed_user_attr_pk"
            primary key,
    "name"                       varchar(255) not null,
    "user_id"                    varchar(255) not null,
    "realm_id"                   varchar(36)  not null,
    "storage_provider_id"        varchar(36),
    "value"                      varchar(2024),
    "long_value_hash"            bytea,
    "long_value_hash_lower_case" bytea,
    "long_value"                 text
)
    /

create index "idx_fu_attribute"
    on "fed_user_attribute" ("user_id", "realm_id", "name")
    /

create index "fed_user_attr_long_values"
    on "fed_user_attribute" ("long_value_hash", "name")
    /

create index "fed_user_attr_long_values_lower_case"
    on "fed_user_attribute" ("long_value_hash_lower_case", "name")
    /

create table "fed_user_consent"
(
    "id"                      varchar(36)  not null
        constraint "constr_fed_user_consent_pk"
            primary key,
    "client_id"               varchar(255),
    "user_id"                 varchar(255) not null,
    "realm_id"                varchar(36)  not null,
    "storage_provider_id"     varchar(36),
    "created_date"            bigint,
    "last_updated_date"       bigint,
    "client_storage_provider" varchar(36),
    "external_client_id"      varchar(255)
)
    /

create index "idx_fu_consent_ru"
    on "fed_user_consent" ("realm_id", "user_id")
    /

create index "idx_fu_cnsnt_ext"
    on "fed_user_consent" ("user_id", "client_storage_provider", "external_client_id")
    /

create index "idx_fu_consent"
    on "fed_user_consent" ("user_id", "client_id")
    /

create table "fed_user_credential"
(
    "id"                  varchar(36)  not null
        constraint "constr_fed_user_cred_pk"
            primary key,
    "salt"                bytea,
    "type"                varchar(255),
    "created_date"        bigint,
    "user_id"             varchar(255) not null,
    "realm_id"            varchar(36)  not null,
    "storage_provider_id" varchar(36),
    "user_label"          varchar(255),
    "secret_data"         text,
    "credential_data"     text,
    "priority"            integer
)
    /

create index "idx_fu_credential"
    on "fed_user_credential" ("user_id", "type")
    /

create index "idx_fu_credential_ru"
    on "fed_user_credential" ("realm_id", "user_id")
    /

create table "fed_user_group_membership"
(
    "group_id"            varchar(36)  not null,
    "user_id"             varchar(255) not null,
    "realm_id"            varchar(36)  not null,
    "storage_provider_id" varchar(36),
    constraint "constr_fed_user_group"
        primary key ("group_id", "user_id")
)
    /

create index "idx_fu_group_membership"
    on "fed_user_group_membership" ("user_id", "group_id")
    /

create index "idx_fu_group_membership_ru"
    on "fed_user_group_membership" ("realm_id", "user_id")
    /

create table "fed_user_required_action"
(
    "required_action"     varchar(255) default ' '::character varying not null,
    "user_id"             varchar(255) not null,
    "realm_id"            varchar(36)  not null,
    "storage_provider_id" varchar(36),
    constraint "constr_fed_required_action"
        primary key ("required_action", "user_id")
)
    /

create index "idx_fu_required_action"
    on "fed_user_required_action" ("user_id", "required_action")
    /

create index "idx_fu_required_action_ru"
    on "fed_user_required_action" ("realm_id", "user_id")
    /

create table "fed_user_role_mapping"
(
    "role_id"             varchar(36)  not null,
    "user_id"             varchar(255) not null,
    "realm_id"            varchar(36)  not null,
    "storage_provider_id" varchar(36),
    constraint "constr_fed_user_role"
        primary key ("role_id", "user_id")
)
    /

create index "idx_fu_role_mapping"
    on "fed_user_role_mapping" ("user_id", "role_id")
    /

create index "idx_fu_role_mapping_ru"
    on "fed_user_role_mapping" ("realm_id", "user_id")
    /

create table "component"
(
    "id"            varchar(36) not null
        constraint "constr_component_pk"
            primary key,
    "name"          varchar(255),
    "parent_id"     varchar(36),
    "provider_id"   varchar(36),
    "provider_type" varchar(255),
    "realm_id"      varchar(36)
        constraint "fk_component_realm"
            references "realm",
    "sub_type"      varchar(255)
)
    /

create table "component_config"
(
    "id"           varchar(36)  not null
        constraint "constr_component_config_pk"
            primary key,
    "component_id" varchar(36)  not null
        constraint "fk_component_config"
            references "component",
    "name"         varchar(255) not null,
    "value"        text
)
    /

create index "idx_compo_config_compo"
    on "component_config" ("component_id")
    /

create index "idx_component_realm"
    on "component" ("realm_id")
    /

create index "idx_component_provider_type"
    on "component" ("provider_type")
    /

create table "federated_user"
(
    "id"                  varchar(255) not null
        constraint "constr_federated_user"
            primary key,
    "storage_provider_id" varchar(255),
    "realm_id"            varchar(36)  not null
)
    /

create table "client_initial_access"
(
    "id"              varchar(36) not null
        constraint "cnstr_client_init_acc_pk"
            primary key,
    "realm_id"        varchar(36) not null
        constraint "fk_client_init_acc_realm"
            references "realm",
    "timestamp"       integer,
    "expiration"      integer,
    "count"           integer,
    "remaining_count" integer
)
    /

create index "idx_client_init_acc_realm"
    on "client_initial_access" ("realm_id")
    /

create table "client_auth_flow_bindings"
(
    "client_id"    varchar(36)  not null,
    "flow_id"      varchar(36),
    "binding_name" varchar(255) not null,
    constraint "c_cli_flow_bind"
        primary key ("client_id", "binding_name")
)
    /

create table "client_scope_client"
(
    "client_id"     varchar(255)          not null,
    "scope_id"      varchar(255)          not null,
    "default_scope" boolean default false not null,
    constraint "c_cli_scope_bind"
        primary key ("client_id", "scope_id")
)
    /

create index "idx_clscope_cl"
    on "client_scope_client" ("client_id")
    /

create index "idx_cl_clscope"
    on "client_scope_client" ("scope_id")
    /

create table "default_client_scope"
(
    "realm_id"      varchar(36)           not null
        constraint "fk_r_def_cli_scope_realm"
            references "realm",
    "scope_id"      varchar(36)           not null,
    "default_scope" boolean default false not null,
    constraint "r_def_cli_scope_bind"
        primary key ("realm_id", "scope_id")
)
    /

create index "idx_defcls_realm"
    on "default_client_scope" ("realm_id")
    /

create index "idx_defcls_scope"
    on "default_client_scope" ("scope_id")
    /

create table "user_consent_client_scope"
(
    "user_consent_id" varchar(36) not null
        constraint "fk_grntcsnt_clsc_usc"
            references "user_consent",
    "scope_id"        varchar(36) not null,
    constraint "constraint_grntcsnt_clsc_pm"
        primary key ("user_consent_id", "scope_id")
)
    /

create index "idx_usconsent_clscope"
    on "user_consent_client_scope" ("user_consent_id")
    /

create index "idx_usconsent_scope_id"
    on "user_consent_client_scope" ("scope_id")
    /

create table "fed_user_consent_cl_scope"
(
    "user_consent_id" varchar(36) not null,
    "scope_id"        varchar(36) not null,
    constraint "constraint_fgrntcsnt_clsc_pm"
        primary key ("user_consent_id", "scope_id")
)
    /

create table "resource_server_perm_ticket"
(
    "id"                 varchar(36)  not null
        constraint "constraint_fapmt"
            primary key,
    "owner"              varchar(255) not null,
    "requester"          varchar(255) not null,
    "created_timestamp"  bigint       not null,
    "granted_timestamp"  bigint,
    "resource_id"        varchar(36)  not null
        constraint "fk_frsrho213xcx4wnkog83sspmt"
            references "resource_server_resource",
    "scope_id"           varchar(36)
        constraint "fk_frsrho213xcx4wnkog84sspmt"
            references "resource_server_scope",
    "resource_server_id" varchar(36)  not null
        constraint "fk_frsrho213xcx4wnkog82sspmt"
            references "resource_server",
    "policy_id"          varchar(36)
        constraint "fk_frsrpo2128cx4wnkog82ssrfy"
            references "resource_server_policy",
    constraint "uk_frsr6t700s9v50bu18ws5pmt"
        unique ("owner", "requester", "resource_server_id", "resource_id", "scope_id")
)
    /

create index "idx_perm_ticket_requester"
    on "resource_server_perm_ticket" ("requester")
    /

create index "idx_perm_ticket_owner"
    on "resource_server_perm_ticket" ("owner")
    /

create table "resource_attribute"
(
    "id"          varchar(36) default 'sybase-needs-something-here'::character varying not null
		constraint "res_attr_pk"
			primary key,
    "name"        varchar(255) not null,
    "value"       varchar(255),
    "resource_id" varchar(36)  not null
        constraint "fk_5hrm2vlf9ql5fu022kqepovbr"
            references "resource_server_resource"
)
    /

create table "resource_uris"
(
    "resource_id" varchar(36)  not null
        constraint "fk_resource_server_uris"
            references "resource_server_resource",
    "value"       varchar(255) not null,
    constraint "constraint_resour_uris_pk"
        primary key ("resource_id", "value")
)
    /

create table "role_attribute"
(
    "id"      varchar(36)  not null
        constraint "constraint_role_attribute_pk"
            primary key,
    "role_id" varchar(36)  not null
        constraint "fk_role_attribute_id"
            references "keycloak_role",
    "name"    varchar(255) not null,
    "value"   varchar(255)
)
    /

create index "idx_role_attribute"
    on "role_attribute" ("role_id")
    /

create table "realm_localizations"
(
    "realm_id" varchar(255) not null,
    "locale"   varchar(255) not null,
    "texts"    text         not null,
    primary key ("realm_id", "locale")
)
    /

create table "org"
(
    "id"           varchar(255) not null
        constraint "ORG_pkey"
            primary key,
    "enabled"      boolean      not null,
    "realm_id"     varchar(255) not null,
    "group_id"     varchar(255) not null
        constraint "uk_org_group"
            unique,
    "name"         varchar(255) not null,
    "description"  varchar(4000),
    "alias"        varchar(255) not null,
    "redirect_url" varchar(2048),
    constraint "uk_org_name"
        unique ("realm_id", "name"),
    constraint "uk_org_alias"
        unique ("realm_id", "alias")
)
    /

create table "org_domain"
(
    "id"       varchar(36)  not null,
    "name"     varchar(255) not null,
    "verified" boolean      not null,
    "org_id"   varchar(255) not null,
    constraint "ORG_DOMAIN_pkey"
        primary key ("id", "name")
)
    /

create index "idx_org_domain_org_id"
    on "org_domain" ("org_id")
    /

create table "revoked_token"
(
    "id"     varchar(255) not null
        constraint "constraint_rt"
            primary key,
    "expire" bigint       not null
)
    /

create index "idx_rev_token_on_expire"
    on "revoked_token" ("expire")
    /

drop synonym DUAL
/

drop synonym MAP_OBJECT
/

drop synonym SYSTEM_PRIVILEGE_MAP
/

drop synonym TABLE_PRIVILEGE_MAP
/

drop synonym USER_PRIVILEGE_MAP
/

drop synonym STMT_AUDIT_OPTION_MAP
/

drop synonym DBMS_STANDARD
/

drop synonym PLITBLM
/

drop synonym V$MAP_LIBRARY
/

drop synonym V$MAP_FILE
/

drop synonym V$MAP_FILE_EXTENT
/

drop synonym V$MAP_ELEMENT
/

drop synonym V$MAP_EXT_ELEMENT
/

drop synonym V$MAP_COMP_LIST
/

drop synonym V$MAP_SUBELEMENT
/

drop synonym V$MAP_FILE_IO_STACK
/

drop synonym V$SQL_REDIRECTION
/

drop synonym V$SQL_PLAN
/

drop synonym V$ALL_SQL_PLAN
/

drop synonym V$SQL_PLAN_STATISTICS
/

drop synonym V$SQL_PLAN_STATISTICS_ALL
/

drop synonym V$ADVISOR_CURRENT_SQLPLAN
/

drop synonym V$SQL_WORKAREA
/

drop synonym V$SQL_WORKAREA_ACTIVE
/

drop synonym V$SQL_WORKAREA_HISTOGRAM
/

drop synonym V$PGA_TARGET_ADVICE
/

drop synonym V$PGA_TARGET_ADVICE_HISTOGRAM
/

drop synonym V$PGASTAT
/

drop synonym V$SYS_OPTIMIZER_ENV
/

drop synonym V$SES_OPTIMIZER_ENV
/

drop synonym V$SQL_OPTIMIZER_ENV
/

drop synonym V$DLM_MISC
/

drop synonym V$DLM_LATCH
/

drop synonym V$DLM_CONVERT_LOCAL
/

drop synonym V$DLM_CONVERT_REMOTE
/

drop synonym V$DLM_ALL_LOCKS
/

drop synonym V$DLM_LOCKS
/

drop synonym V$DLM_RESS
/

drop synonym V$HVMASTER_INFO
/

drop synonym V$GCSHVMASTER_INFO
/

drop synonym V$GCSPFMASTER_INFO
/

drop synonym GV$DLM_TRAFFIC_CONTROLLER
/

drop synonym V$DLM_TRAFFIC_CONTROLLER
/

drop synonym GV$DYNAMIC_REMASTER_STATS
/

drop synonym V$DYNAMIC_REMASTER_STATS
/

drop synonym V$GES_ENQUEUE
/

drop synonym V$GES_BLOCKING_ENQUEUE
/

drop synonym V$GC_ELEMENT
/

drop synonym V$CR_BLOCK_SERVER
/

drop synonym V$CURRENT_BLOCK_SERVER
/

drop synonym V$POLICY_HISTORY
/

drop synonym V$GC_ELEMENTS_WITH_COLLISIONS
/

drop synonym V$FILE_CACHE_TRANSFER
/

drop synonym V$TEMP_CACHE_TRANSFER
/

drop synonym V$CLASS_CACHE_TRANSFER
/

drop synonym V$BH
/

drop synonym V$SQLFN_METADATA
/

drop synonym V$SQLFN_ARG_METADATA
/

drop synonym V$LOCK_ELEMENT
/

drop synonym V$LOCKS_WITH_COLLISIONS
/

drop synonym V$FILE_PING
/

drop synonym V$TEMP_PING
/

drop synonym V$CLASS_PING
/

drop synonym V$INSTANCE_CACHE_TRANSFER
/

drop synonym V$BUFFER_POOL
/

drop synonym V$BUFFER_POOL_STATISTICS
/

drop synonym V$BT_SCAN_OBJ_TEMPS
/

drop synonym GV$BT_SCAN_OBJ_TEMPS
/

drop synonym V$BT_SCAN_CACHE
/

drop synonym GV$BT_SCAN_CACHE
/

drop synonym V$INSTANCE_RECOVERY
/

drop synonym V$CONTROLFILE
/

drop synonym V$LOG
/

drop synonym V$STANDBY_LOG
/

drop synonym V$DATAGUARD_STATUS
/

drop synonym V$THREAD
/

drop synonym V$PROCESS
/

drop synonym V$BGPROCESS
/

drop synonym V$SESSION
/

drop synonym V$LICENSE
/

drop synonym V$TRANSACTION
/

drop synonym V$BSP
/

drop synonym V$FAST_START_SERVERS
/

drop synonym V$FAST_START_TRANSACTIONS
/

drop synonym V$LOCKED_OBJECT
/

drop synonym V$LATCH
/

drop synonym V$LATCH_CHILDREN
/

drop synonym V$LATCH_PARENT
/

drop synonym V$LATCHNAME
/

drop synonym V$LATCHHOLDER
/

drop synonym V$LATCH_MISSES
/

drop synonym V$SESSION_LONGOPS
/

drop synonym V$RESOURCE
/

drop synonym V$_LOCK
/

drop synonym V$LOCK
/

drop synonym V$SESSTAT
/

drop synonym V$MYSTAT
/

drop synonym V$SUBCACHE
/

drop synonym V$SYSSTAT
/

drop synonym V$CON_SYSSTAT
/

drop synonym V$STATNAME
/

drop synonym V$OSSTAT
/

drop synonym V$ACCESS
/

drop synonym V$OBJECT_DEPENDENCY
/

drop synonym V$DBFILE
/

drop synonym V$FLASHFILESTAT
/

drop synonym V$FILESTAT
/

drop synonym V$TEMPSTAT
/

drop synonym V$LOGFILE
/

drop synonym V$FLASHBACK_DATABASE_LOGFILE
/

drop synonym V$FLASHBACK_DATABASE_LOG
/

drop synonym V$FLASHBACK_DATABASE_STAT
/

drop synonym V$RESTORE_POINT
/

drop synonym V$ROLLNAME
/

drop synonym V$ROLLSTAT
/

drop synonym V$UNDOSTAT
/

drop synonym V$TEMPUNDOSTAT
/

drop synonym GV$TEMPUNDOSTAT
/

drop synonym V$SGA
/

drop synonym V$CLUSTER_INTERCONNECTS
/

drop synonym V$CONFIGURED_INTERCONNECTS
/

drop synonym V$PARAMETER
/

drop synonym V$PARAMETER2
/

drop synonym V$OBSOLETE_PARAMETER
/

drop synonym V$SYSTEM_PARAMETER
/

drop synonym V$SYSTEM_PARAMETER2
/

drop synonym GV$SYSTEM_RESET_PARAMETER
/

drop synonym V$SYSTEM_RESET_PARAMETER
/

drop synonym GV$SYSTEM_RESET_PARAMETER2
/

drop synonym V$SYSTEM_RESET_PARAMETER2
/

drop synonym V$SPPARAMETER
/

drop synonym V$PARAMETER_VALID_VALUES
/

drop synonym V$ROWCACHE
/

drop synonym V$ROWCACHE_PARENT
/

drop synonym V$ROWCACHE_SUBORDINATE
/

drop synonym V$ENABLEDPRIVS
/

drop synonym V$NLS_PARAMETERS
/

drop synonym V$NLS_VALID_VALUES
/

drop synonym V$LIBRARYCACHE
/

drop synonym V$LIBCACHE_LOCKS
/

drop synonym V$TYPE_SIZE
/

drop synonym V$ARCHIVE
/

drop synonym V$CIRCUIT
/

drop synonym V$DATABASE
/

drop synonym V$INSTANCE
/

drop synonym V$DISPATCHER
/

drop synonym V$DISPATCHER_CONFIG
/

drop synonym V$DISPATCHER_RATE
/

drop synonym V$LOGHIST
/

drop synonym V$SQLAREA
/

drop synonym V$SQLAREA_PLAN_HASH
/

drop synonym V$SQLTEXT
/

drop synonym V$SQLTEXT_WITH_NEWLINES
/

drop synonym V$SQL
/

drop synonym V$SQL_SHARED_CURSOR
/

drop synonym V$DB_PIPES
/

drop synonym V$DB_OBJECT_CACHE
/

drop synonym V$OPEN_CURSOR
/

drop synonym V$OPTION
/

drop synonym V$VERSION
/

drop synonym V$PQ_SESSTAT
/

drop synonym V$PQ_SYSSTAT
/

drop synonym V$PQ_SLAVE
/

drop synonym V$QUEUE
/

drop synonym V$SHARED_SERVER_MONITOR
/

drop synonym V$DBLINK
/

drop synonym V$PWFILE_USERS
/

drop synonym V$PASSWORDFILE_INFO
/

drop synonym V$REQDIST
/

drop synonym V$SGASTAT
/

drop synonym V$SGAINFO
/

drop synonym V$WAITSTAT
/

drop synonym V$SHARED_SERVER
/

drop synonym V$TIMER
/

drop synonym V$RECOVER_FILE
/

drop synonym V$BACKUP
/

drop synonym V$BACKUP_SET
/

drop synonym V$BACKUP_PIECE
/

drop synonym V$BACKUP_DATAFILE
/

drop synonym V$BACKUP_SPFILE
/

drop synonym V$BACKUP_REDOLOG
/

drop synonym V$BACKUP_CORRUPTION
/

drop synonym V$COPY_CORRUPTION
/

drop synonym V$DATABASE_BLOCK_CORRUPTION
/

drop synonym V$MTTR_TARGET_ADVICE
/

drop synonym V$STATISTICS_LEVEL
/

drop synonym V$DELETED_OBJECT
/

drop synonym V$PROXY_DATAFILE
/

drop synonym V$PROXY_ARCHIVEDLOG
/

drop synonym V$CONTROLFILE_RECORD_SECTION
/

drop synonym V$ARCHIVED_LOG
/

drop synonym V$FOREIGN_ARCHIVED_LOG
/

drop synonym V$OFFLINE_RANGE
/

drop synonym V$DATAFILE_COPY
/

drop synonym V$LOG_HISTORY
/

drop synonym V$RECOVERY_LOG
/

drop synonym V$ARCHIVE_GAP
/

drop synonym V$DATAFILE_HEADER
/

drop synonym V$DATAFILE
/

drop synonym V$TEMPFILE
/

drop synonym V$TABLESPACE
/

drop synonym V$BACKUP_DEVICE
/

drop synonym V$MANAGED_STANDBY
/

drop synonym V$ARCHIVE_PROCESSES
/

drop synonym V$ARCHIVE_DEST
/

drop synonym V$REDO_DEST_RESP_HISTOGRAM
/

drop synonym V$DATAGUARD_CONFIG
/

drop synonym V$DATAGUARD_STATS
/

drop synonym V$FIXED_TABLE
/

drop synonym V$FIXED_VIEW_DEFINITION
/

drop synonym V$INDEXED_FIXED_COLUMN
/

drop synonym V$SESSION_CURSOR_CACHE
/

drop synonym V$SESSION_WAIT_CLASS
/

drop synonym V$SESSION_WAIT
/

drop synonym V$SESSION_WAIT_HISTORY
/

drop synonym V$SESSION_BLOCKERS
/

drop synonym V$WAIT_CHAINS
/

drop synonym V$SESSION_EVENT
/

drop synonym V$SESSION_CONNECT_INFO
/

drop synonym V$SYSTEM_WAIT_CLASS
/

drop synonym V$CON_SYSTEM_WAIT_CLASS
/

drop synonym V$SYSTEM_EVENT
/

drop synonym V$CON_SYSTEM_EVENT
/

drop synonym V$EVENT_NAME
/

drop synonym V$EVENT_HISTOGRAM
/

drop synonym V$EVENT_HISTOGRAM_MICRO
/

drop synonym V$CON_EVENT_HISTOGRAM_MICRO
/

drop synonym V$EVENT_OUTLIERS
/

drop synonym V$FILE_HISTOGRAM
/

drop synonym V$FILE_OPTIMIZED_HISTOGRAM
/

drop synonym V$EXECUTION
/

drop synonym V$SYSTEM_CURSOR_CACHE
/

drop synonym V$SESS_IO
/

drop synonym V$RECOVERY_STATUS
/

drop synonym V$RECOVERY_FILE_STATUS
/

drop synonym V$RECOVERY_PROGRESS
/

drop synonym V$SHARED_POOL_RESERVED
/

drop synonym V$SORT_SEGMENT
/

drop synonym V$TEMPSEG_USAGE
/

drop synonym V$SORT_USAGE
/

drop synonym V$RESOURCE_LIMIT
/

drop synonym V$ENQUEUE_LOCK
/

drop synonym V$TRANSACTION_ENQUEUE
/

drop synonym V$PQ_TQSTAT
/

drop synonym V$ACTIVE_INSTANCES
/

drop synonym V$SQL_CURSOR
/

drop synonym V$SQL_BIND_METADATA
/

drop synonym V$SQL_BIND_DATA
/

drop synonym V$SQL_SHARED_MEMORY
/

drop synonym V$GLOBAL_TRANSACTION
/

drop synonym V$SESSION_OBJECT_CACHE
/

drop synonym V$LOCK_ACTIVITY
/

drop synonym V$AQ1
/

drop synonym V$HS_AGENT
/

drop synonym V$HS_SESSION
/

drop synonym V$HS_PARAMETER
/

drop synonym V$RSRC_CONSUMER_GROUP_CPU_MTH
/

drop synonym V$RSRC_PLAN_CPU_MTH
/

drop synonym V$RSRC_CONSUMER_GROUP
/

drop synonym V$RSRC_SESSION_INFO
/

drop synonym V$RSRC_PLAN
/

drop synonym V$RSRC_CONS_GROUP_HISTORY
/

drop synonym V$RSRC_PLAN_HISTORY
/

drop synonym V$BLOCKING_QUIESCE
/

drop synonym V$PX_BUFFER_ADVICE
/

drop synonym V$PX_SESSION
/

drop synonym V$PX_SESSTAT
/

drop synonym V$BACKUP_SYNC_IO
/

drop synonym V$BACKUP_ASYNC_IO
/

drop synonym V$TEMPORARY_LOBS
/

drop synonym V$PX_PROCESS
/

drop synonym V$PX_PROCESS_SYSSTAT
/

drop synonym V$PX_PROCESS_TRACE
/

drop synonym GV$PX_PROCESS_TRACE
/

drop synonym V$LOGMNR_CONTENTS
/

drop synonym V$LOGMNR_PARAMETERS
/

drop synonym V$LOGMNR_DICTIONARY
/

drop synonym V$LOGMNR_LOGS
/

drop synonym V$LOGMNR_STATS
/

drop synonym V$LOGMNR_DICTIONARY_LOAD
/

drop synonym V$RFS_THREAD
/

drop synonym V$STANDBY_EVENT_HISTOGRAM
/

drop synonym V$GLOBAL_BLOCKED_LOCKS
/

drop synonym V$AW_OLAP
/

drop synonym V$AW_CALC
/

drop synonym V$AW_SESSION_INFO
/

drop synonym GV$AW_AGGREGATE_OP
/

drop synonym V$AW_AGGREGATE_OP
/

drop synonym GV$AW_ALLOCATE_OP
/

drop synonym V$AW_ALLOCATE_OP
/

drop synonym V$AW_LONGOPS
/

drop synonym V$MAX_ACTIVE_SESS_TARGET_MTH
/

drop synonym V$ACTIVE_SESS_POOL_MTH
/

drop synonym V$PARALLEL_DEGREE_LIMIT_MTH
/

drop synonym V$QUEUEING_MTH
/

drop synonym V$RESERVED_WORDS
/

drop synonym V$ARCHIVE_DEST_STATUS
/

drop synonym V$DB_CACHE_ADVICE
/

drop synonym V$SGA_TARGET_ADVICE
/

drop synonym V$MEMORY_TARGET_ADVICE
/

drop synonym V$MEMORY_RESIZE_OPS
/

drop synonym V$MEMORY_CURRENT_RESIZE_OPS
/

drop synonym V$MEMORY_DYNAMIC_COMPONENTS
/

drop synonym GV$MEMORY_TARGET_ADVICE
/

drop synonym GV$MEMORY_RESIZE_OPS
/

drop synonym GV$MEMORY_CURRENT_RESIZE_OPS
/

drop synonym GV$MEMORY_DYNAMIC_COMPONENTS
/

drop synonym V$SEGMENT_STATISTICS
/

drop synonym V$SEGSTAT_NAME
/

drop synonym V$SEGSTAT
/

drop synonym V$LIBRARY_CACHE_MEMORY
/

drop synonym V$JAVA_LIBRARY_CACHE_MEMORY
/

drop synonym V$SHARED_POOL_ADVICE
/

drop synonym V$JAVA_POOL_ADVICE
/

drop synonym V$STREAMS_POOL_ADVICE
/

drop synonym V$GOLDENGATE_CAPABILITIES
/

drop synonym V$SGA_CURRENT_RESIZE_OPS
/

drop synonym V$SGA_RESIZE_OPS
/

drop synonym V$SGA_DYNAMIC_COMPONENTS
/

drop synonym V$SGA_DYNAMIC_FREE_MEMORY
/

drop synonym V$RESUMABLE
/

drop synonym V$TIMEZONE_NAMES
/

drop synonym V$TIMEZONE_FILE
/

drop synonym V$ENQUEUE_STAT
/

drop synonym V$ENQUEUE_STATISTICS
/

drop synonym V$LOCK_TYPE
/

drop synonym V$RMAN_CONFIGURATION
/

drop synonym V$DATABASE_INCARNATION
/

drop synonym V$METRIC
/

drop synonym V$METRIC_HISTORY
/

drop synonym V$SYSMETRIC
/

drop synonym V$SYSMETRIC_HISTORY
/

drop synonym V$METRICNAME
/

drop synonym V$METRICGROUP
/

drop synonym V$SERVICE_WAIT_CLASS
/

drop synonym V$SERVICE_EVENT
/

drop synonym V$ACTIVE_SERVICES
/

drop synonym V$SERVICES
/

drop synonym V$SYSMETRIC_SUMMARY
/

drop synonym V$CON_SYSMETRIC
/

drop synonym V$CON_SYSMETRIC_HISTORY
/

drop synonym V$CON_SYSMETRIC_SUMMARY
/

drop synonym V$SESSMETRIC
/

drop synonym V$FILEMETRIC
/

drop synonym V$FILEMETRIC_HISTORY
/

drop synonym V$EVENTMETRIC
/

drop synonym V$WAITCLASSMETRIC
/

drop synonym V$WAITCLASSMETRIC_HISTORY
/

drop synonym V$SERVICEMETRIC
/

drop synonym V$SERVICEMETRIC_HISTORY
/

drop synonym V$IOFUNCMETRIC
/

drop synonym V$IOFUNCMETRIC_HISTORY
/

drop synonym V$RSRCMGRMETRIC
/

drop synonym V$RSRCMGRMETRIC_HISTORY
/

drop synonym V$RSRCPDBMETRIC
/

drop synonym V$RSRCPDBMETRIC_HISTORY
/

drop synonym V$RSRC_PDB
/

drop synonym V$RSRC_PDB_HISTORY
/

drop synonym V$WLM_PCMETRIC
/

drop synonym V$WLM_PCMETRIC_HISTORY
/

drop synonym V$WLM_PC_STATS
/

drop synonym V$WLM_DB_MODE
/

drop synonym V$WLM_PCSERVICE
/

drop synonym V$ADVISOR_PROGRESS
/

drop synonym GV$SQLPA_METRIC
/

drop synonym V$SQLPA_METRIC
/

drop synonym V$XML_AUDIT_TRAIL
/

drop synonym V$SQL_JOIN_FILTER
/

drop synonym V$PROCESS_MEMORY
/

drop synonym V$PROCESS_MEMORY_DETAIL
/

drop synonym V$PROCESS_MEMORY_DETAIL_PROG
/

drop synonym V$SQLSTATS
/

drop synonym V$SQLSTATS_PLAN_HASH
/

drop synonym V$MUTEX_SLEEP
/

drop synonym V$MUTEX_SLEEP_HISTORY
/

drop synonym V$OBJECT_PRIVILEGE
/

drop synonym V$CALLTAG
/

drop synonym V$PROCESS_GROUP
/

drop synonym V$DETACHED_SESSION
/

drop synonym V$MAPPED_SQL
/

drop synonym GV$MUTEX_SLEEP
/

drop synonym GV$MUTEX_SLEEP_HISTORY
/

drop synonym GV$SQLSTATS
/

drop synonym GV$SQLSTATS_PLAN_HASH
/

drop synonym GV$MAP_LIBRARY
/

drop synonym GV$MAP_FILE
/

drop synonym GV$MAP_FILE_EXTENT
/

drop synonym GV$MAP_ELEMENT
/

drop synonym GV$MAP_EXT_ELEMENT
/

drop synonym GV$MAP_COMP_LIST
/

drop synonym GV$MAP_SUBELEMENT
/

drop synonym GV$MAP_FILE_IO_STACK
/

drop synonym GV$BSP
/

drop synonym GV$OBSOLETE_PARAMETER
/

drop synonym GV$FAST_START_SERVERS
/

drop synonym GV$FAST_START_TRANSACTIONS
/

drop synonym GV$ENQUEUE_LOCK
/

drop synonym GV$TRANSACTION_ENQUEUE
/

drop synonym GV$RESOURCE_LIMIT
/

drop synonym GV$SQL_REDIRECTION
/

drop synonym GV$SQL_PLAN
/

drop synonym GV$ALL_SQL_PLAN
/

drop synonym GV$SQL_PLAN_STATISTICS
/

drop synonym GV$SQL_PLAN_STATISTICS_ALL
/

drop synonym GV$ADVISOR_CURRENT_SQLPLAN
/

drop synonym GV$SQL_WORKAREA
/

drop synonym GV$SQL_WORKAREA_ACTIVE
/

drop synonym GV$SQL_WORKAREA_HISTOGRAM
/

drop synonym GV$PGA_TARGET_ADVICE
/

drop synonym GV$PGA_TARGET_ADVICE_HISTOGRAM
/

drop synonym GV$PGASTAT
/

drop synonym GV$SYS_OPTIMIZER_ENV
/

drop synonym GV$SES_OPTIMIZER_ENV
/

drop synonym GV$SQL_OPTIMIZER_ENV
/

drop synonym GV$DLM_MISC
/

drop synonym GV$DLM_LATCH
/

drop synonym GV$DLM_CONVERT_LOCAL
/

drop synonym GV$DLM_CONVERT_REMOTE
/

drop synonym GV$DLM_ALL_LOCKS
/

drop synonym GV$DLM_LOCKS
/

drop synonym GV$DLM_RESS
/

drop synonym GV$HVMASTER_INFO
/

drop synonym GV$GCSHVMASTER_INFO
/

drop synonym GV$GCSPFMASTER_INFO
/

drop synonym GV$GES_ENQUEUE
/

drop synonym GV$GES_BLOCKING_ENQUEUE
/

drop synonym GV$GC_ELEMENT
/

drop synonym GV$CR_BLOCK_SERVER
/

drop synonym GV$CURRENT_BLOCK_SERVER
/

drop synonym GV$POLICY_HISTORY
/

drop synonym GV$GC_ELEMENTS_WITH_COLLISIONS
/

drop synonym GV$FILE_CACHE_TRANSFER
/

drop synonym GV$TEMP_CACHE_TRANSFER
/

drop synonym GV$CLASS_CACHE_TRANSFER
/

drop synonym GV$BH
/

drop synonym GV$SQLFN_METADATA
/

drop synonym GV$SQLFN_ARG_METADATA
/

drop synonym GV$LOCK_ELEMENT
/

drop synonym GV$LOCKS_WITH_COLLISIONS
/

drop synonym GV$FILE_PING
/

drop synonym GV$TEMP_PING
/

drop synonym GV$CLASS_PING
/

drop synonym GV$INSTANCE_CACHE_TRANSFER
/

drop synonym GV$BUFFER_POOL
/

drop synonym GV$BUFFER_POOL_STATISTICS
/

drop synonym GV$INSTANCE_RECOVERY
/

drop synonym GV$CONTROLFILE
/

drop synonym GV$LOG
/

drop synonym GV$STANDBY_LOG
/

drop synonym GV$DATAGUARD_STATUS
/

drop synonym GV$THREAD
/

drop synonym GV$PROCESS
/

drop synonym GV$BGPROCESS
/

drop synonym GV$SESSION
/

drop synonym GV$LICENSE
/

drop synonym GV$TRANSACTION
/

drop synonym GV$LOCKED_OBJECT
/

drop synonym GV$LATCH
/

drop synonym GV$LATCH_CHILDREN
/

drop synonym GV$LATCH_PARENT
/

drop synonym GV$LATCHNAME
/

drop synonym GV$LATCHHOLDER
/

drop synonym GV$LATCH_MISSES
/

drop synonym GV$SESSION_LONGOPS
/

drop synonym GV$RESOURCE
/

drop synonym GV$_LOCK
/

drop synonym GV$LOCK
/

drop synonym GV$SESSTAT
/

drop synonym GV$MYSTAT
/

drop synonym GV$SUBCACHE
/

drop synonym GV$SYSSTAT
/

drop synonym GV$CON_SYSSTAT
/

drop synonym GV$STATNAME
/

drop synonym GV$OSSTAT
/

drop synonym GV$ACCESS
/

drop synonym GV$OBJECT_DEPENDENCY
/

drop synonym GV$DBFILE
/

drop synonym GV$DATAFILE
/

drop synonym GV$TEMPFILE
/

drop synonym GV$TABLESPACE
/

drop synonym GV$FLASHFILESTAT
/

drop synonym GV$FILESTAT
/

drop synonym GV$TEMPSTAT
/

drop synonym GV$LOGFILE
/

drop synonym GV$FLASHBACK_DATABASE_LOGFILE
/

drop synonym GV$FLASHBACK_DATABASE_LOG
/

drop synonym GV$FLASHBACK_DATABASE_STAT
/

drop synonym GV$RESTORE_POINT
/

drop synonym GV$ROLLSTAT
/

drop synonym GV$UNDOSTAT
/

drop synonym GV$SGA
/

drop synonym GV$CLUSTER_INTERCONNECTS
/

drop synonym GV$CONFIGURED_INTERCONNECTS
/

drop synonym GV$PARAMETER
/

drop synonym GV$PARAMETER2
/

drop synonym GV$SYSTEM_PARAMETER
/

drop synonym GV$SYSTEM_PARAMETER2
/

drop synonym GV$SPPARAMETER
/

drop synonym GV$PARAMETER_VALID_VALUES
/

drop synonym GV$ROWCACHE
/

drop synonym GV$ROWCACHE_PARENT
/

drop synonym GV$ROWCACHE_SUBORDINATE
/

drop synonym GV$ENABLEDPRIVS
/

drop synonym GV$NLS_PARAMETERS
/

drop synonym GV$NLS_VALID_VALUES
/

drop synonym GV$LIBRARYCACHE
/

drop synonym GV$LIBCACHE_LOCKS
/

drop synonym GV$TYPE_SIZE
/

drop synonym GV$ARCHIVE
/

drop synonym GV$CIRCUIT
/

drop synonym GV$DATABASE
/

drop synonym GV$INSTANCE
/

drop synonym GV$DISPATCHER
/

drop synonym GV$DISPATCHER_CONFIG
/

drop synonym GV$DISPATCHER_RATE
/

drop synonym GV$LOGHIST
/

drop synonym GV$SQLAREA
/

drop synonym GV$SQLAREA_PLAN_HASH
/

drop synonym GV$SQLTEXT
/

drop synonym GV$SQLTEXT_WITH_NEWLINES
/

drop synonym GV$SQL
/

drop synonym GV$SQL_SHARED_CURSOR
/

drop synonym GV$DB_PIPES
/

drop synonym GV$DB_OBJECT_CACHE
/

drop synonym GV$OPEN_CURSOR
/

drop synonym GV$OPTION
/

drop synonym GV$VERSION
/

drop synonym GV$PQ_SESSTAT
/

drop synonym GV$PQ_SYSSTAT
/

drop synonym GV$PQ_SLAVE
/

drop synonym GV$QUEUE
/

drop synonym GV$SHARED_SERVER_MONITOR
/

drop synonym GV$DBLINK
/

drop synonym GV$PWFILE_USERS
/

drop synonym GV$PASSWORDFILE_INFO
/

drop synonym GV$REQDIST
/

drop synonym GV$SGASTAT
/

drop synonym GV$SGAINFO
/

drop synonym GV$WAITSTAT
/

drop synonym GV$SHARED_SERVER
/

drop synonym GV$TIMER
/

drop synonym GV$RECOVER_FILE
/

drop synonym GV$BACKUP
/

drop synonym GV$BACKUP_SET
/

drop synonym GV$BACKUP_PIECE
/

drop synonym GV$BACKUP_DATAFILE
/

drop synonym GV$BACKUP_SPFILE
/

drop synonym GV$BACKUP_REDOLOG
/

drop synonym GV$BACKUP_CORRUPTION
/

drop synonym GV$COPY_CORRUPTION
/

drop synonym GV$DATABASE_BLOCK_CORRUPTION
/

drop synonym GV$MTTR_TARGET_ADVICE
/

drop synonym GV$STATISTICS_LEVEL
/

drop synonym GV$DELETED_OBJECT
/

drop synonym GV$PROXY_DATAFILE
/

drop synonym GV$PROXY_ARCHIVEDLOG
/

drop synonym GV$CONTROLFILE_RECORD_SECTION
/

drop synonym GV$ARCHIVED_LOG
/

drop synonym GV$FOREIGN_ARCHIVED_LOG
/

drop synonym GV$OFFLINE_RANGE
/

drop synonym GV$DATAFILE_COPY
/

drop synonym GV$LOG_HISTORY
/

drop synonym GV$RECOVERY_LOG
/

drop synonym GV$ARCHIVE_GAP
/

drop synonym GV$DATAFILE_HEADER
/

drop synonym GV$BACKUP_DEVICE
/

drop synonym GV$MANAGED_STANDBY
/

drop synonym GV$ARCHIVE_PROCESSES
/

drop synonym GV$ARCHIVE_DEST
/

drop synonym GV$REDO_DEST_RESP_HISTOGRAM
/

drop synonym GV$DATAGUARD_CONFIG
/

drop synonym GV$FIXED_TABLE
/

drop synonym GV$FIXED_VIEW_DEFINITION
/

drop synonym GV$INDEXED_FIXED_COLUMN
/

drop synonym GV$SESSION_CURSOR_CACHE
/

drop synonym GV$SESSION_WAIT_CLASS
/

drop synonym GV$SESSION_WAIT
/

drop synonym GV$SESSION_WAIT_HISTORY
/

drop synonym GV$SESSION_BLOCKERS
/

drop synonym GV$SESSION_EVENT
/

drop synonym GV$SESSION_CONNECT_INFO
/

drop synonym GV$SYSTEM_WAIT_CLASS
/

drop synonym GV$CON_SYSTEM_WAIT_CLASS
/

drop synonym GV$SYSTEM_EVENT
/

drop synonym GV$CON_SYSTEM_EVENT
/

drop synonym GV$EVENT_NAME
/

drop synonym GV$EVENT_HISTOGRAM
/

drop synonym GV$EVENT_HISTOGRAM_MICRO
/

drop synonym GV$CON_EVENT_HISTOGRAM_MICRO
/

drop synonym GV$EVENT_OUTLIERS
/

drop synonym GV$FILE_HISTOGRAM
/

drop synonym GV$FILE_OPTIMIZED_HISTOGRAM
/

drop synonym GV$EXECUTION
/

drop synonym GV$SYSTEM_CURSOR_CACHE
/

drop synonym GV$SESS_IO
/

drop synonym GV$RECOVERY_STATUS
/

drop synonym GV$RECOVERY_FILE_STATUS
/

drop synonym GV$RECOVERY_PROGRESS
/

drop synonym GV$SHARED_POOL_RESERVED
/

drop synonym GV$SORT_SEGMENT
/

drop synonym GV$TEMPSEG_USAGE
/

drop synonym GV$SORT_USAGE
/

drop synonym GV$PQ_TQSTAT
/

drop synonym GV$ACTIVE_INSTANCES
/

drop synonym GV$SQL_CURSOR
/

drop synonym GV$SQL_BIND_METADATA
/

drop synonym GV$SQL_BIND_DATA
/

drop synonym GV$SQL_SHARED_MEMORY
/

drop synonym GV$GLOBAL_TRANSACTION
/

drop synonym GV$SESSION_OBJECT_CACHE
/

drop synonym GV$AQ1
/

drop synonym GV$LOCK_ACTIVITY
/

drop synonym GV$HS_AGENT
/

drop synonym GV$HS_SESSION
/

drop synonym GV$HS_PARAMETER
/

drop synonym GV$RSRC_CONSUMER_GROUP_CPU_MTH
/

drop synonym GV$RSRC_PLAN_CPU_MTH
/

drop synonym GV$RSRC_CONSUMER_GROUP
/

drop synonym GV$RSRC_SESSION_INFO
/

drop synonym GV$RSRC_PLAN
/

drop synonym GV$RSRC_CONS_GROUP_HISTORY
/

drop synonym GV$RSRC_PLAN_HISTORY
/

drop synonym GV$BLOCKING_QUIESCE
/

drop synonym GV$PX_BUFFER_ADVICE
/

drop synonym GV$PX_SESSION
/

drop synonym GV$PX_SESSTAT
/

drop synonym GV$BACKUP_SYNC_IO
/

drop synonym GV$BACKUP_ASYNC_IO
/

drop synonym GV$TEMPORARY_LOBS
/

drop synonym GV$PX_PROCESS
/

drop synonym GV$PX_PROCESS_SYSSTAT
/

drop synonym GV$LOGMNR_CONTENTS
/

drop synonym GV$LOGMNR_PARAMETERS
/

drop synonym GV$LOGMNR_DICTIONARY
/

drop synonym GV$LOGMNR_LOGS
/

drop synonym GV$RFS_THREAD
/

drop synonym GV$DATAGUARD_STATS
/

drop synonym GV$GLOBAL_BLOCKED_LOCKS
/

drop synonym GV$AW_OLAP
/

drop synonym GV$AW_CALC
/

drop synonym GV$AW_SESSION_INFO
/

drop synonym GV$AW_LONGOPS
/

drop synonym GV$MAX_ACTIVE_SESS_TARGET_MTH
/

drop synonym GV$ACTIVE_SESS_POOL_MTH
/

drop synonym GV$PARALLEL_DEGREE_LIMIT_MTH
/

drop synonym GV$QUEUEING_MTH
/

drop synonym GV$RESERVED_WORDS
/

drop synonym GV$ARCHIVE_DEST_STATUS
/

drop synonym V$LOGMNR_LOGFILE
/

drop synonym V$LOGMNR_PROCESS
/

drop synonym V$LOGMNR_LATCH
/

drop synonym V$LOGMNR_TRANSACTION
/

drop synonym V$LOGMNR_SESSION
/

drop synonym GV$LOGMNR_LOGFILE
/

drop synonym GV$LOGMNR_PROCESS
/

drop synonym GV$LOGMNR_LATCH
/

drop synonym GV$LOGMNR_TRANSACTION
/

drop synonym GV$LOGMNR_SESSION
/

drop synonym GV$LOGMNR_STATS
/

drop synonym GV$LOGMNR_DICTIONARY_LOAD
/

drop synonym GV$DB_CACHE_ADVICE
/

drop synonym GV$SGA_TARGET_ADVICE
/

drop synonym GV$SEGMENT_STATISTICS
/

drop synonym GV$SEGSTAT_NAME
/

drop synonym GV$SEGSTAT
/

drop synonym GV$LIBRARY_CACHE_MEMORY
/

drop synonym GV$JAVA_LIBRARY_CACHE_MEMORY
/

drop synonym GV$SHARED_POOL_ADVICE
/

drop synonym GV$JAVA_POOL_ADVICE
/

drop synonym GV$STREAMS_POOL_ADVICE
/

drop synonym GV$GOLDENGATE_CAPABILITIES
/

drop synonym GV$SGA_CURRENT_RESIZE_OPS
/

drop synonym GV$SGA_RESIZE_OPS
/

drop synonym GV$SGA_DYNAMIC_COMPONENTS
/

drop synonym GV$SGA_DYNAMIC_FREE_MEMORY
/

drop synonym GV$RESUMABLE
/

drop synonym GV$TIMEZONE_NAMES
/

drop synonym GV$TIMEZONE_FILE
/

drop synonym GV$ENQUEUE_STAT
/

drop synonym GV$ENQUEUE_STATISTICS
/

drop synonym GV$LOCK_TYPE
/

drop synonym GV$RMAN_CONFIGURATION
/

drop synonym GV$VPD_POLICY
/

drop synonym V$VPD_POLICY
/

drop synonym GV$DATABASE_INCARNATION
/

drop synonym GV$ASM_TEMPLATE
/

drop synonym V$ASM_TEMPLATE
/

drop synonym GV$ASM_FILE
/

drop synonym V$ASM_FILE
/

drop synonym GV$ASM_DISKGROUP
/

drop synonym V$ASM_DISKGROUP
/

drop synonym GV$ASM_DISKGROUP_STAT
/

drop synonym V$ASM_DISKGROUP_STAT
/

drop synonym GV$ASM_DISKGROUP_SPARSE
/

drop synonym V$ASM_DISKGROUP_SPARSE
/

drop synonym GV$ASM_DISK
/

drop synonym V$ASM_DISK
/

drop synonym GV$ASM_DISK_STAT
/

drop synonym V$ASM_DISK_STAT
/

drop synonym GV$ASM_DISK_SPARSE
/

drop synonym V$ASM_DISK_SPARSE
/

drop synonym GV$ASM_DISK_SPARSE_STAT
/

drop synonym V$ASM_DISK_SPARSE_STAT
/

drop synonym GV$ASM_DISK_IOSTAT_SPARSE
/

drop synonym V$ASM_DISK_IOSTAT_SPARSE
/

drop synonym GV$ASM_CLIENT
/

drop synonym V$ASM_CLIENT
/

drop synonym GV$IOS_CLIENT
/

drop synonym V$IOS_CLIENT
/

drop synonym GV$ASM_ALIAS
/

drop synonym V$ASM_ALIAS
/

drop synonym GV$ASM_ATTRIBUTE
/

drop synonym V$ASM_ATTRIBUTE
/

drop synonym GV$ASM_OPERATION
/

drop synonym V$ASM_OPERATION
/

drop synonym GV$ASM_USER
/

drop synonym V$ASM_USER
/

drop synonym GV$ASM_USERGROUP
/

drop synonym V$ASM_USERGROUP
/

drop synonym GV$ASM_USERGROUP_MEMBER
/

drop synonym V$ASM_USERGROUP_MEMBER
/

drop synonym GV$ASM_ESTIMATE
/

drop synonym V$ASM_ESTIMATE
/

drop synonym GV$ASM_AUDIT_CLEAN_EVENTS
/

drop synonym V$ASM_AUDIT_CLEAN_EVENTS
/

drop synonym GV$ASM_AUDIT_CLEANUP_JOBS
/

drop synonym V$ASM_AUDIT_CLEANUP_JOBS
/

drop synonym GV$ASM_AUDIT_CONFIG_PARAMS
/

drop synonym V$ASM_AUDIT_CONFIG_PARAMS
/

drop synonym GV$ASM_AUDIT_LAST_ARCH_TS
/

drop synonym V$ASM_AUDIT_LAST_ARCH_TS
/

drop synonym GV$ASM_AUDIT_LOAD_JOBS
/

drop synonym V$ASM_AUDIT_LOAD_JOBS
/

drop synonym GV$ASM_DBCLONE_INFO
/

drop synonym V$ASM_DBCLONE_INFO
/

drop synonym V$ASM_CACHE_EVENTS
/

drop synonym GV$RULE_SET
/

drop synonym V$RULE_SET
/

drop synonym GV$RULE
/

drop synonym V$RULE
/

drop synonym GV$RULE_SET_AGGREGATE_STATS
/

drop synonym V$RULE_SET_AGGREGATE_STATS
/

drop synonym GV$JAVAPOOL
/

drop synonym V$JAVAPOOL
/

drop synonym GV$SYSAUX_OCCUPANTS
/

drop synonym V$SYSAUX_OCCUPANTS
/

drop synonym V$RMAN_STATUS
/

drop synonym V$RMAN_OUTPUT
/

drop synonym GV$RMAN_OUTPUT
/

drop synonym V$RECOVERY_FILE_DEST
/

drop synonym V$FLASH_RECOVERY_AREA_USAGE
/

drop synonym V$RECOVERY_AREA_USAGE
/

drop synonym V$BLOCK_CHANGE_TRACKING
/

drop synonym GV$METRIC
/

drop synonym GV$METRIC_HISTORY
/

drop synonym GV$SYSMETRIC
/

drop synonym GV$SYSMETRIC_HISTORY
/

drop synonym GV$METRICNAME
/

drop synonym GV$METRICGROUP
/

drop synonym GV$ACTIVE_SESSION_HISTORY
/

drop synonym V$ACTIVE_SESSION_HISTORY
/

drop synonym GV$ALL_ACTIVE_SESSION_HISTORY
/

drop synonym V$ALL_ACTIVE_SESSION_HISTORY
/

drop synonym GV$ASH_INFO
/

drop synonym V$ASH_INFO
/

drop synonym GV$RT_ADDM_CONTROL
/

drop synonym V$RT_ADDM_CONTROL
/

drop synonym GV$INSTANCE_PING
/

drop synonym V$INSTANCE_PING
/

drop synonym GV$WORKLOAD_REPLAY_THREAD
/

drop synonym V$WORKLOAD_REPLAY_THREAD
/

drop synonym GV$INSTANCE_LOG_GROUP
/

drop synonym V$INSTANCE_LOG_GROUP
/

drop synonym GV$SERVICE_WAIT_CLASS
/

drop synonym GV$SERVICE_EVENT
/

drop synonym GV$ACTIVE_SERVICES
/

drop synonym GV$SERVICES
/

drop synonym V$SCHEDULER_RUNNING_JOBS
/

drop synonym GV$SCHEDULER_RUNNING_JOBS
/

drop synonym V$SCHEDULER_INMEM_RTINFO
/

drop synonym GV$SCHEDULER_INMEM_RTINFO
/

drop synonym V$SCHEDULER_INMEM_MDINFO
/

drop synonym GV$SCHEDULER_INMEM_MDINFO
/

drop synonym GV$BUFFERED_QUEUES
/

drop synonym V$BUFFERED_QUEUES
/

drop synonym GV$BUFFERED_SUBSCRIBERS
/

drop synonym V$BUFFERED_SUBSCRIBERS
/

drop synonym GV$BUFFERED_PUBLISHERS
/

drop synonym V$BUFFERED_PUBLISHERS
/

drop synonym GV$TSM_SESSIONS
/

drop synonym V$TSM_SESSIONS
/

drop synonym GV$PROPAGATION_SENDER
/

drop synonym V$PROPAGATION_SENDER
/

drop synonym GV$PROPAGATION_RECEIVER
/

drop synonym V$PROPAGATION_RECEIVER
/

drop synonym GV$SUBSCR_REGISTRATION_STATS
/

drop synonym V$SUBSCR_REGISTRATION_STATS
/

drop synonym GV$EMON
/

drop synonym V$EMON
/

drop synonym V$AQ_NOTIFICATION_CLIENTS
/

drop synonym GV$AQ_NOTIFICATION_CLIENTS
/

drop synonym V$AQ_BACKGROUND_COORDINATOR
/

drop synonym GV$AQ_BACKGROUND_COORDINATOR
/

drop synonym V$AQ_JOB_COORDINATOR
/

drop synonym GV$AQ_JOB_COORDINATOR
/

drop synonym V$AQ_SERVER_POOL
/

drop synonym GV$AQ_SERVER_POOL
/

drop synonym V$AQ_CROSS_INSTANCE_JOBS
/

drop synonym GV$AQ_CROSS_INSTANCE_JOBS
/

drop synonym GV$CON_SYSMETRIC
/

drop synonym GV$CON_SYSMETRIC_HISTORY
/

drop synonym GV$CON_SYSMETRIC_SUMMARY
/

drop synonym GV$SYSMETRIC_SUMMARY
/

drop synonym GV$SESSMETRIC
/

drop synonym GV$FILEMETRIC
/

drop synonym GV$FILEMETRIC_HISTORY
/

drop synonym GV$EVENTMETRIC
/

drop synonym GV$WAITCLASSMETRIC
/

drop synonym GV$WAITCLASSMETRIC_HISTORY
/

drop synonym GV$SERVICEMETRIC
/

drop synonym GV$SERVICEMETRIC_HISTORY
/

drop synonym GV$IOFUNCMETRIC
/

drop synonym GV$IOFUNCMETRIC_HISTORY
/

drop synonym GV$RSRCMGRMETRIC
/

drop synonym GV$RSRCMGRMETRIC_HISTORY
/

drop synonym GV$RSRCPDBMETRIC
/

drop synonym GV$RSRCPDBMETRIC_HISTORY
/

drop synonym GV$RSRC_PDB
/

drop synonym GV$RSRC_PDB_HISTORY
/

drop synonym GV$WLM_PCMETRIC
/

drop synonym GV$WLM_PCMETRIC_HISTORY
/

drop synonym GV$WLM_PC_STATS
/

drop synonym GV$WLM_DB_MODE
/

drop synonym GV$WLM_PCSERVICE
/

drop synonym GV$ADVISOR_PROGRESS
/

drop synonym GV$XML_AUDIT_TRAIL
/

drop synonym GV$SQL_JOIN_FILTER
/

drop synonym GV$PROCESS_MEMORY
/

drop synonym GV$PROCESS_MEMORY_DETAIL
/

drop synonym GV$PROCESS_MEMORY_DETAIL_PROG
/

drop synonym GV$WALLET
/

drop synonym V$WALLET
/

drop synonym GV$SYSTEM_FIX_CONTROL
/

drop synonym V$SYSTEM_FIX_CONTROL
/

drop synonym GV$SESSION_FIX_CONTROL
/

drop synonym V$SESSION_FIX_CONTROL
/

drop synonym GV$SQL_DIAG_REPOSITORY
/

drop synonym V$SQL_DIAG_REPOSITORY
/

drop synonym GV$SQL_DIAG_REPOSITORY_REASON
/

drop synonym V$SQL_DIAG_REPOSITORY_REASON
/

drop synonym GV$FS_FAILOVER_HISTOGRAM
/

drop synonym V$FS_FAILOVER_HISTOGRAM
/

drop synonym GV$SQL_FEATURE
/

drop synonym V$SQL_FEATURE
/

drop synonym GV$SQL_FEATURE_HIERARCHY
/

drop synonym V$SQL_FEATURE_HIERARCHY
/

drop synonym GV$SQL_FEATURE_DEPENDENCY
/

drop synonym V$SQL_FEATURE_DEPENDENCY
/

drop synonym GV$SQL_HINT
/

drop synonym V$SQL_HINT
/

drop synonym GV$RESULT_CACHE_STATISTICS
/

drop synonym V$RESULT_CACHE_STATISTICS
/

drop synonym GV$RESULT_CACHE_MEMORY
/

drop synonym V$RESULT_CACHE_MEMORY
/

drop synonym GV$RESULT_CACHE_OBJECTS
/

drop synonym V$RESULT_CACHE_OBJECTS
/

drop synonym GV$RESULT_CACHE_DEPENDENCY
/

drop synonym V$RESULT_CACHE_DEPENDENCY
/

drop synonym GV$GWM_RAC_AFFINITY
/

drop synonym GV$SQL_CS_HISTOGRAM
/

drop synonym V$SQL_CS_HISTOGRAM
/

drop synonym GV$SQL_CS_SELECTIVITY
/

drop synonym V$SQL_CS_SELECTIVITY
/

drop synonym GV$SQL_CS_STATISTICS
/

drop synonym V$SQL_CS_STATISTICS
/

drop synonym GV$INDEX_USAGE_INFO
/

drop synonym V$INDEX_USAGE_INFO
/

drop synonym GV$SQL_MONITOR
/

drop synonym V$SQL_MONITOR
/

drop synonym GV$SQL_PLAN_MONITOR
/

drop synonym V$SQL_PLAN_MONITOR
/

drop synonym V$SQL_MONITOR_STATNAME
/

drop synonym GV$SQL_MONITOR_STATNAME
/

drop synonym V$SQL_MONITOR_SESSTAT
/

drop synonym GV$SQL_MONITOR_SESSTAT
/

drop synonym GV$ALL_SQL_MONITOR
/

drop synonym V$ALL_SQL_MONITOR
/

drop synonym GV$ALL_SQL_PLAN_MONITOR
/

drop synonym V$ALL_SQL_PLAN_MONITOR
/

drop synonym GV$MAPPED_SQL
/

drop synonym NLS_SESSION_PARAMETERS
/

drop synonym NLS_INSTANCE_PARAMETERS
/

drop synonym NLS_DATABASE_PARAMETERS
/

drop synonym DATABASE_COMPATIBLE_LEVEL
/

drop synonym PRODUCT_COMPONENT_VERSION
/

drop synonym V$TRANSPORTABLE_PLATFORM
/

drop synonym GV$TRANSPORTABLE_PLATFORM
/

drop synonym V$DB_TRANSPORTABLE_PLATFORM
/

drop synonym GV$DB_TRANSPORTABLE_PLATFORM
/

drop synonym V$IOSTAT_NETWORK
/

drop synonym GV$IOSTAT_NETWORK
/

drop synonym GV$CPOOL_CC_STATS
/

drop synonym V$CPOOL_CC_STATS
/

drop synonym GV$CPOOL_CC_INFO
/

drop synonym V$CPOOL_CC_INFO
/

drop synonym GV$CPOOL_STATS
/

drop synonym V$CPOOL_STATS
/

drop synonym GV$CPOOL_CONN_INFO
/

drop synonym V$CPOOL_CONN_INFO
/

drop synonym GV$HM_RUN
/

drop synonym V$HM_RUN
/

drop synonym GV$HM_FINDING
/

drop synonym V$HM_FINDING
/

drop synonym GV$HM_RECOMMENDATION
/

drop synonym V$HM_RECOMMENDATION
/

drop synonym GV$HM_INFO
/

drop synonym V$HM_INFO
/

drop synonym GV$HM_CHECK
/

drop synonym V$HM_CHECK
/

drop synonym GV$HM_CHECK_PARAM
/

drop synonym V$HM_CHECK_PARAM
/

drop synonym GV$IR_FAILURE
/

drop synonym V$IR_FAILURE
/

drop synonym GV$IR_REPAIR
/

drop synonym V$IR_REPAIR
/

drop synonym GV$IR_MANUAL_CHECKLIST
/

drop synonym V$IR_MANUAL_CHECKLIST
/

drop synonym GV$IR_FAILURE_SET
/

drop synonym V$IR_FAILURE_SET
/

drop synonym V$PX_INSTANCE_GROUP
/

drop synonym GV$PX_INSTANCE_GROUP
/

drop synonym V$IOSTAT_CONSUMER_GROUP
/

drop synonym GV$IOSTAT_CONSUMER_GROUP
/

drop synonym V$IOSTAT_FUNCTION
/

drop synonym GV$IOSTAT_FUNCTION
/

drop synonym V$IOSTAT_FUNCTION_DETAIL
/

drop synonym GV$IOSTAT_FUNCTION_DETAIL
/

drop synonym V$IOSTAT_FILE
/

drop synonym GV$IOSTAT_FILE
/

drop synonym V$IO_CALIBRATION_STATUS
/

drop synonym GV$IO_CALIBRATION_STATUS
/

drop synonym GV$CORRUPT_XID_LIST
/

drop synonym GV$CALLTAG
/

drop synonym V$CORRUPT_XID_LIST
/

drop synonym GV$PERSISTENT_QUEUES
/

drop synonym V$PERSISTENT_QUEUES
/

drop synonym GV$PERSISTENT_SUBSCRIBERS
/

drop synonym V$PERSISTENT_SUBSCRIBERS
/

drop synonym GV$PERSISTENT_PUBLISHERS
/

drop synonym V$PERSISTENT_PUBLISHERS
/

drop synonym V$AQ_NONDUR_SUBSCRIBER
/

drop synonym GV$AQ_NONDUR_SUBSCRIBER
/

drop synonym V$AQ_NONDUR_SUBSCRIBER_LWM
/

drop synonym GV$AQ_NONDUR_SUBSCRIBER_LWM
/

drop synonym V$AQ_BMAP_NONDUR_SUBSCRIBERS
/

drop synonym GV$AQ_BMAP_NONDUR_SUBSCRIBERS
/

drop synonym GV$AQ_SUBSCRIBER_LOAD
/

drop synonym V$AQ_SUBSCRIBER_LOAD
/

drop synonym GV$AQ_REMOTE_DEQUEUE_AFFINITY
/

drop synonym V$AQ_REMOTE_DEQUEUE_AFFINITY
/

drop synonym GV$AQ_MESSAGE_CACHE_STAT
/

drop synonym V$AQ_MESSAGE_CACHE_STAT
/

drop synonym GV$AQ_CACHED_SUBSHARDS
/

drop synonym V$AQ_CACHED_SUBSHARDS
/

drop synonym GV$AQ_UNCACHED_SUBSHARDS
/

drop synonym V$AQ_UNCACHED_SUBSHARDS
/

drop synonym GV$AQ_INACTIVE_SUBSHARDS
/

drop synonym V$AQ_INACTIVE_SUBSHARDS
/

drop synonym GV$AQ_MESSAGE_CACHE_ADVICE
/

drop synonym V$AQ_MESSAGE_CACHE_ADVICE
/

drop synonym GV$AQ_SHARDED_SUBSCRIBER_STAT
/

drop synonym V$AQ_SHARDED_SUBSCRIBER_STAT
/

drop synonym GV$AQ_PARTITION_STATS
/

drop synonym V$AQ_PARTITION_STATS
/

drop synonym GV$RO_USER_ACCOUNT
/

drop synonym V$RO_USER_ACCOUNT
/

drop synonym GV$PROCESS_GROUP
/

drop synonym GV$DETACHED_SESSION
/

drop synonym GV$SSCR_SESSIONS
/

drop synonym V$SSCR_SESSIONS
/

drop synonym GV$NFS_CLIENTS
/

drop synonym V$NFS_CLIENTS
/

drop synonym GV$NFS_OPEN_FILES
/

drop synonym V$NFS_OPEN_FILES
/

drop synonym GV$NFS_LOCKS
/

drop synonym V$NFS_LOCKS
/

drop synonym V$RMAN_COMPRESSION_ALGORITHM
/

drop synonym GV$RMAN_COMPRESSION_ALGORITHM
/

drop synonym V$ENCRYPTION_WALLET
/

drop synonym GV$ENCRYPTION_WALLET
/

drop synonym V$ENCRYPTED_TABLESPACES
/

drop synonym GV$ENCRYPTED_TABLESPACES
/

drop synonym V$DATABASE_KEY_INFO
/

drop synonym GV$DATABASE_KEY_INFO
/

drop synonym V$ENCRYPTION_KEYS
/

drop synonym GV$ENCRYPTION_KEYS
/

drop synonym V$CLIENT_SECRETS
/

drop synonym GV$CLIENT_SECRETS
/

drop synonym GV$INCMETER_CONFIG
/

drop synonym V$INCMETER_CONFIG
/

drop synonym GV$INCMETER_SUMMARY
/

drop synonym V$INCMETER_SUMMARY
/

drop synonym GV$INCMETER_INFO
/

drop synonym V$INCMETER_INFO
/

drop synonym GV$DNFS_STATS
/

drop synonym V$DNFS_STATS
/

drop synonym GV$DNFS_FILES
/

drop synonym V$DNFS_FILES
/

drop synonym GV$DNFS_SERVERS
/

drop synonym V$DNFS_SERVERS
/

drop synonym GV$ASM_VOLUME
/

drop synonym V$ASM_VOLUME
/

drop synonym GV$ASM_VOLUME_STAT
/

drop synonym V$ASM_VOLUME_STAT
/

drop synonym GV$ASM_FILESYSTEM
/

drop synonym V$ASM_FILESYSTEM
/

drop synonym GV$ASM_ACFSVOLUMES
/

drop synonym V$ASM_ACFSVOLUMES
/

drop synonym GV$ASM_ACFSSNAPSHOTS
/

drop synonym V$ASM_ACFSSNAPSHOTS
/

drop synonym GV$ASM_ACFSTAG
/

drop synonym V$ASM_ACFSTAG
/

drop synonym GV$ASM_ACFSAUTORESIZE
/

drop synonym V$ASM_ACFSAUTORESIZE
/

drop synonym GV$ASM_ACFS_SECURITY_INFO
/

drop synonym V$ASM_ACFS_SECURITY_INFO
/

drop synonym GV$ASM_ACFS_ENCRYPTION_INFO
/

drop synonym V$ASM_ACFS_ENCRYPTION_INFO
/

drop synonym GV$ASM_ACFS_SEC_RULE
/

drop synonym V$ASM_ACFS_SEC_RULE
/

drop synonym GV$ASM_ACFS_SEC_REALM
/

drop synonym V$ASM_ACFS_SEC_REALM
/

drop synonym GV$ASM_ACFS_SEC_REALM_USER
/

drop synonym V$ASM_ACFS_SEC_REALM_USER
/

drop synonym GV$ASM_ACFS_SEC_REALM_GROUP
/

drop synonym V$ASM_ACFS_SEC_REALM_GROUP
/

drop synonym GV$ASM_ACFS_SEC_REALM_FILTER
/

drop synonym V$ASM_ACFS_SEC_REALM_FILTER
/

drop synonym GV$ASM_ACFS_SEC_RULESET
/

drop synonym V$ASM_ACFS_SEC_RULESET
/

drop synonym GV$ASM_ACFS_SEC_RULESET_RULE
/

drop synonym V$ASM_ACFS_SEC_RULESET_RULE
/

drop synonym GV$ASM_ACFS_SEC_CMDRULE
/

drop synonym V$ASM_ACFS_SEC_CMDRULE
/

drop synonym GV$ASM_ACFS_SEC_ADMIN
/

drop synonym V$ASM_ACFS_SEC_ADMIN
/

drop synonym GV$ASM_ACFSREPL
/

drop synonym V$ASM_ACFSREPL
/

drop synonym GV$ASM_ACFSREPLTAG
/

drop synonym V$ASM_ACFSREPLTAG
/

drop synonym V$FLASHBACK_TXN_MODS
/

drop synonym V$FLASHBACK_TXN_GRAPH
/

drop synonym GV$LOBSTAT
/

drop synonym V$LOBSTAT
/

drop synonym GV$FS_FAILOVER_STATS
/

drop synonym V$FS_FAILOVER_STATS
/

drop synonym GV$ASM_DISK_IOSTAT
/

drop synonym V$ASM_DISK_IOSTAT
/

drop synonym GV$DIAG_INFO
/

drop synonym V$DIAG_INFO
/

drop synonym GV$SECUREFILE_TIMER
/

drop synonym V$SECUREFILE_TIMER
/

drop synonym GV$DNFS_CHANNELS
/

drop synonym V$DNFS_CHANNELS
/

drop synonym V$DIAG_CRITICAL_ERROR
/

drop synonym GV$CELL_STATE
/

drop synonym V$CELL_STATE
/

drop synonym GV$CELL_THREAD_HISTORY
/

drop synonym V$CELL_THREAD_HISTORY
/

drop synonym GV$CELL_OFL_THREAD_HISTORY
/

drop synonym V$CELL_OFL_THREAD_HISTORY
/

drop synonym GV$CELL_REQUEST_TOTALS
/

drop synonym V$CELL_REQUEST_TOTALS
/

drop synonym GV$CELL
/

drop synonym V$CELL
/

drop synonym GV$CELL_CONFIG
/

drop synonym V$CELL_CONFIG
/

drop synonym GV$CELL_CONFIG_INFO
/

drop synonym V$CELL_CONFIG_INFO
/

drop synonym GV$CELL_METRIC_DESC
/

drop synonym V$CELL_METRIC_DESC
/

drop synonym GV$CELL_GLOBAL
/

drop synonym V$CELL_GLOBAL
/

drop synonym GV$CELL_GLOBAL_HISTORY
/

drop synonym V$CELL_GLOBAL_HISTORY
/

drop synonym GV$CELL_DISK
/

drop synonym V$CELL_DISK
/

drop synonym GV$CELL_DISK_HISTORY
/

drop synonym V$CELL_DISK_HISTORY
/

drop synonym GV$CELL_IOREASON
/

drop synonym V$CELL_IOREASON
/

drop synonym GV$CELL_IOREASON_NAME
/

drop synonym V$CELL_IOREASON_NAME
/

drop synonym GV$CELL_DB
/

drop synonym V$CELL_DB
/

drop synonym GV$CELL_DB_HISTORY
/

drop synonym V$CELL_DB_HISTORY
/

drop synonym GV$CELL_OPEN_ALERTS
/

drop synonym V$CELL_OPEN_ALERTS
/

drop synonym GV$QMON_COORDINATOR_STATS
/

drop synonym V$QMON_COORDINATOR_STATS
/

drop synonym GV$QMON_SERVER_STATS
/

drop synonym V$QMON_SERVER_STATS
/

drop synonym GV$QMON_TASKS
/

drop synonym V$QMON_TASKS
/

drop synonym GV$QMON_TASK_STATS
/

drop synonym V$QMON_TASK_STATS
/

drop synonym GV$PERSISTENT_QMN_CACHE
/

drop synonym V$PERSISTENT_QMN_CACHE
/

drop synonym GV$OBJECT_DML_FREQUENCIES
/

drop synonym V$OBJECT_DML_FREQUENCIES
/

drop synonym GV$LISTENER_NETWORK
/

drop synonym V$LISTENER_NETWORK
/

drop synonym GV$SQLCOMMAND
/

drop synonym V$SQLCOMMAND
/

drop synonym GV$TOPLEVELCALL
/

drop synonym V$TOPLEVELCALL
/

drop synonym V$HANG_INFO
/

drop synonym V$HANG_SESSION_INFO
/

drop synonym V$HANG_STATISTICS
/

drop synonym GV$HANG_STATISTICS
/

drop synonym V$SEGSPACE_USAGE
/

drop synonym GV$SEGSPACE_USAGE
/

drop synonym V$BTS_STAT
/

drop synonym GV$BTS_STAT
/

drop synonym V$PDBS
/

drop synonym GV$PDBS
/

drop synonym V$CONTAINERS
/

drop synonym GV$CONTAINERS
/

drop synonym V$PROXY_PDB_TARGETS
/

drop synonym GV$PROXY_PDB_TARGETS
/

drop synonym V$PDB_INCARNATION
/

drop synonym GV$PDB_INCARNATION
/

drop synonym V$GES_DEADLOCKS
/

drop synonym GV$GES_DEADLOCKS
/

drop synonym V$GES_DEADLOCK_SESSIONS
/

drop synonym GV$GES_DEADLOCK_SESSIONS
/

drop synonym V$XS_SESSION_ROLES
/

drop synonym V$XS_SESSION_ROLE
/

drop synonym GV$XS_SESSION_ROLES
/

drop synonym GV$XS_SESSION_ROLE
/

drop synonym V$XS_SESSION_NS_ATTRIBUTES
/

drop synonym V$XS_SESSION_NS_ATTRIBUTE
/

drop synonym GV$XS_SESSION_NS_ATTRIBUTES
/

drop synonym GV$XS_SESSION_NS_ATTRIBUTE
/

drop synonym V$XS_SESSIONS
/

drop synonym GV$XS_SESSIONS
/

drop synonym V$PING
/

drop synonym GV$PING
/

drop synonym V$CACHE
/

drop synonym GV$CACHE
/

drop synonym V$FALSE_PING
/

drop synonym GV$FALSE_PING
/

drop synonym V$CACHE_TRANSFER
/

drop synonym GV$CACHE_TRANSFER
/

drop synonym V$CACHE_LOCK
/

drop synonym GV$CACHE_LOCK
/

drop synonym V$UNIFIED_AUDIT_TRAIL
/

drop synonym GV$UNIFIED_AUDIT_TRAIL
/

drop synonym V$UNIFIED_AUDIT_RECORD_FORMAT
/

drop synonym V$DG_BROKER_CONFIG
/

drop synonym GV$DG_BROKER_CONFIG
/

drop synonym V$EDITIONABLE_TYPES
/

drop synonym GV$EDITIONABLE_TYPES
/

drop synonym V$REPLAY_CONTEXT
/

drop synonym GV$REPLAY_CONTEXT
/

drop synonym V$REPLAY_CONTEXT_SYSDATE
/

drop synonym GV$REPLAY_CONTEXT_SYSDATE
/

drop synonym V$REPLAY_CONTEXT_SYSTIMESTAMP
/

drop synonym GV$REPLAY_CONTEXT_SYSTIMESTAMP
/

drop synonym V$REPLAY_CONTEXT_SYSGUID
/

drop synonym GV$REPLAY_CONTEXT_SYSGUID
/

drop synonym V$REPLAY_CONTEXT_SEQUENCE
/

drop synonym GV$REPLAY_CONTEXT_SEQUENCE
/

drop synonym V$REPLAY_CONTEXT_LOB
/

drop synonym GV$REPLAY_CONTEXT_LOB
/

drop synonym V$OFSMOUNT
/

drop synonym GV$OFSMOUNT
/

drop synonym V$OFS_STATS
/

drop synonym GV$OFS_STATS
/

drop synonym V$IO_OUTLIER
/

drop synonym GV$IO_OUTLIER
/

drop synonym V$LGWRIO_OUTLIER
/

drop synonym GV$LGWRIO_OUTLIER
/

drop synonym V$KERNEL_IO_OUTLIER
/

drop synonym GV$KERNEL_IO_OUTLIER
/

drop synonym V$PATCHES
/

drop synonym GV$PATCHES
/

drop synonym X$KXFTASK
/

drop synonym V$NONLOGGED_BLOCK
/

drop synonym GV$NONLOGGED_BLOCK
/

drop synonym V$COPY_NONLOGGED
/

drop synonym GV$COPY_NONLOGGED
/

drop synonym V$BACKUP_NONLOGGED
/

drop synonym GV$BACKUP_NONLOGGED
/

drop synonym V$SQL_REOPTIMIZATION_HINTS
/

drop synonym GV$SQL_REOPTIMIZATION_HINTS
/

drop synonym V$OPTIMIZER_PROCESSING_RATE
/

drop synonym GV$OPTIMIZER_PROCESSING_RATE
/

drop synonym V$HEAT_MAP_SEGMENT
/

drop synonym GV$HEAT_MAP_SEGMENT
/

drop synonym V$SYS_REPORT_STATS
/

drop synonym GV$SYS_REPORT_STATS
/

drop synonym V$SYS_REPORT_REQUESTS
/

drop synonym GV$SYS_REPORT_REQUESTS
/

drop synonym V$CLONEDFILE
/

drop synonym GV$CLONEDFILE
/

drop synonym V$AQ_MSGBM
/

drop synonym GV$AQ_MSGBM
/

drop synonym V$CON_SYS_TIME_MODEL
/

drop synonym GV$CON_SYS_TIME_MODEL
/

drop synonym V$AQ_NONDUR_REGISTRATIONS
/

drop synonym GV$AQ_NONDUR_REGISTRATIONS
/

drop synonym V$AQ_MESSAGE_CACHE
/

drop synonym GV$AQ_MESSAGE_CACHE
/

drop synonym V$CHANNEL_WAITS
/

drop synonym GV$CHANNEL_WAITS
/

drop synonym V$TSDP_SUPPORTED_FEATURE
/

drop synonym GV$TSDP_SUPPORTED_FEATURE
/

drop synonym V$DEAD_CLEANUP
/

drop synonym GV$DEAD_CLEANUP
/

drop synonym V$SESSIONS_COUNT
/

drop synonym GV$SESSIONS_COUNT
/

drop synonym GV$AUTO_BMR_STATISTICS
/

drop synonym V$IM_SEGMENTS_DETAIL
/

drop synonym GV$IM_SEGMENTS_DETAIL
/

drop synonym V$IM_SEGMENTS
/

drop synonym GV$IM_SEGMENTS
/

drop synonym V$IM_USER_SEGMENTS
/

drop synonym GV$IM_USER_SEGMENTS
/

drop synonym V$INMEMORY_AREA
/

drop synonym GV$INMEMORY_AREA
/

drop synonym V$IM_TBS_EXT_MAP
/

drop synonym GV$IM_TBS_EXT_MAP
/

drop synonym V$IM_SEG_EXT_MAP
/

drop synonym GV$IM_SEG_EXT_MAP
/

drop synonym V$IM_HEADER
/

drop synonym GV$IM_HEADER
/

drop synonym V$IM_DELTA_HEADER
/

drop synonym GV$IM_DELTA_HEADER
/

drop synonym V$IM_COL_CU
/

drop synonym GV$IM_COL_CU
/

drop synonym V$IM_SMU_HEAD
/

drop synonym GV$IM_SMU_HEAD
/

drop synonym V$IM_SMU_DELTA
/

drop synonym GV$IM_SMU_DELTA
/

drop synonym V$IM_SMU_CHUNK
/

drop synonym GV$IM_SMU_CHUNK
/

drop synonym V$IM_COLUMN_LEVEL
/

drop synonym GV$IM_COLUMN_LEVEL
/

drop synonym V$INMEMORY_FASTSTART_AREA
/

drop synonym GV$INMEMORY_FASTSTART_AREA
/

drop synonym V$IM_GLOBALDICT
/

drop synonym GV$IM_GLOBALDICT
/

drop synonym V$IM_GLOBALDICT_VERSION
/

drop synonym GV$IM_GLOBALDICT_VERSION
/

drop synonym V$IM_GLOBALDICT_SORTORDER
/

drop synonym GV$IM_GLOBALDICT_SORTORDER
/

drop synonym V$IM_GLOBALDICT_PIECEMAP
/

drop synonym GV$IM_GLOBALDICT_PIECEMAP
/

drop synonym V$IMEU_HEADER
/

drop synonym GV$IMEU_HEADER
/

drop synonym V$IM_IMECOL_CU
/

drop synonym GV$IM_IMECOL_CU
/

drop synonym V$INMEMORY_XMEM_AREA
/

drop synonym GV$INMEMORY_XMEM_AREA
/

drop synonym GV$FS_OBSERVER_HISTOGRAM
/

drop synonym V$FS_OBSERVER_HISTOGRAM
/

drop synonym V$KEY_VECTOR
/

drop synonym GV$KEY_VECTOR
/

drop synonym V$RECOVERY_SLAVE
/

drop synonym GV$RECOVERY_SLAVE
/

drop synonym GV$EMX_USAGE_STATS
/

drop synonym V$EMX_USAGE_STATS
/

drop synonym GV$PROCESS_PRIORITY_DATA
/

drop synonym V$PROCESS_PRIORITY_DATA
/

drop synonym GV$QPX_INVENTORY
/

drop synonym V$QPX_INVENTORY
/

drop synonym GV$DATAGUARD_PROCESS
/

drop synonym V$DATAGUARD_PROCESS
/

drop synonym V$ONLINE_REDEF
/

drop synonym GV$ONLINE_REDEF
/

drop synonym V$CLEANUP_PROCESS
/

drop synonym GV$CLEANUP_PROCESS
/

drop synonym GV$ZONEMAP_USAGE_STATS
/

drop synonym V$ZONEMAP_USAGE_STATS
/

drop synonym GV$CODE_CLAUSE
/

drop synonym V$CODE_CLAUSE
/

drop synonym GV$GCR_METRICS
/

drop synonym V$GCR_METRICS
/

drop synonym GV$GCR_ACTIONS
/

drop synonym V$GCR_ACTIONS
/

drop synonym GV$GCR_STATUS
/

drop synonym V$GCR_STATUS
/

drop synonym GV$GCR_LOG
/

drop synonym V$GCR_LOG
/

drop synonym V$STATS_ADVISOR_RULES
/

drop synonym V$STATS_ADVISOR_FINDINGS
/

drop synonym V$STATS_ADVISOR_RECS
/

drop synonym V$STATS_ADVISOR_RATIONALES
/

drop synonym V$STATS_ADVISOR_ACTIONS
/

drop synonym V$PROCESS_POOL
/

drop synonym GV$PROCESS_POOL
/

drop synonym GV$ASM_FILEGROUP
/

drop synonym V$ASM_FILEGROUP
/

drop synonym GV$ASM_FILEGROUP_PROPERTY
/

drop synonym V$ASM_FILEGROUP_PROPERTY
/

drop synonym GV$ASM_FILEGROUP_FILE
/

drop synonym V$ASM_FILEGROUP_FILE
/

drop synonym GV$ASM_QUOTAGROUP
/

drop synonym V$ASM_QUOTAGROUP
/

drop synonym GV$SHADOW_DATAFILE
/

drop synonym V$SHADOW_DATAFILE
/

drop synonym V$EXADIRECT_ACL
/

drop synonym GV$EXADIRECT_ACL
/

drop synonym V$QUARANTINE
/

drop synonym GV$QUARANTINE
/

drop synonym V$QUARANTINE_SUMMARY
/

drop synonym GV$QUARANTINE_SUMMARY
/

drop synonym GV$SERVICE_REGION_METRIC
/

drop synonym V$SERVICE_REGION_METRIC
/

drop synonym GV$CHUNK_METRIC
/

drop synonym V$CHUNK_METRIC
/

drop synonym GV$FS_FAILOVER_OBSERVERS
/

drop synonym V$FS_FAILOVER_OBSERVERS
/

drop synonym V$COLUMN_STATISTICS
/

drop synonym GV$COLUMN_STATISTICS
/

drop synonym V$IM_ADOELEMENTS
/

drop synonym GV$IM_ADOELEMENTS
/

drop synonym V$IM_ADOTASKS
/

drop synonym GV$IM_ADOTASKS
/

drop synonym V$IM_ADOTASKDETAILS
/

drop synonym GV$IM_ADOTASKDETAILS
/

drop synonym GV$IP_ACL
/

drop synonym V$IP_ACL
/

drop synonym V$TEMPFILE_INFO_INSTANCE
/

drop synonym GV$TEMPFILE_INFO_INSTANCE
/

drop synonym V$EXP_STATS
/

drop synonym GV$EXP_STATS
/

drop synonym V$DML_STATS
/

drop synonym GV$DML_STATS
/

drop synonym GV$DIAG_TRACE_FILE
/

drop synonym V$DIAG_TRACE_FILE
/

drop synonym GV$DIAG_APP_TRACE_FILE
/

drop synonym V$DIAG_APP_TRACE_FILE
/

drop synonym GV$DIAG_TRACE_FILE_CONTENTS
/

drop synonym V$DIAG_TRACE_FILE_CONTENTS
/

drop synonym GV$DIAG_SQL_TRACE_RECORDS
/

drop synonym V$DIAG_SQL_TRACE_RECORDS
/

drop synonym GV$DIAG_OPT_TRACE_RECORDS
/

drop synonym V$DIAG_OPT_TRACE_RECORDS
/

drop synonym V$DIAG_SESS_SQL_TRACE_RECORDS
/

drop synonym V$DIAG_SESS_OPT_TRACE_RECORDS
/

drop synonym GV$PLSQL_DEBUGGABLE_SESSIONS
/

drop synonym V$PLSQL_DEBUGGABLE_SESSIONS
/

drop synonym GV$AQ_IPC_ACTIVE_MSGS
/

drop synonym V$AQ_IPC_ACTIVE_MSGS
/

drop synonym GV$AQ_IPC_PENDING_MSGS
/

drop synonym V$AQ_IPC_PENDING_MSGS
/

drop synonym GV$AQ_IPC_MSG_STATS
/

drop synonym V$AQ_IPC_MSG_STATS
/

drop synonym GV$LOCKDOWN_RULES
/

drop synonym V$LOCKDOWN_RULES
/

drop synonym V$SQL_SHARD
/

drop synonym GV$SQL_SHARD
/

drop synonym GV$JAVA_SERVICES
/

drop synonym V$JAVA_SERVICES
/

drop synonym GV$JAVA_PATCHING_STATUS
/

drop synonym V$JAVA_PATCHING_STATUS
/

drop synonym V$MEMOPTIMIZE_WRITE_AREA
/

drop synonym GV$MEMOPTIMIZE_WRITE_AREA
/

drop synonym GV$DATABASE_REPLAY_PROGRESS
/

drop synonym V$DATABASE_REPLAY_PROGRESS
/

drop synonym V$IMHMSEG
/

drop synonym GV$IMHMSEG
/

drop synonym GV$DUAL
/

drop synonym V$DUAL
/

drop synonym V$SQL_TESTCASES
/

drop synonym GV$SQL_TESTCASES
/

drop synonym GV$NOLOGGING_STANDBY_TXN
/

drop synonym V$NOLOGGING_STANDBY_TXN
/

drop synonym V$MY_NOLOGGING_STANDBY_TXN
/

drop synonym GV$SHARED_SERVER_STAT
/

drop synonym V$SHARED_SERVER_STAT
/

drop synonym DBA_KGLLOCK
/

drop synonym CDB_KGLLOCK
/

drop synonym DBA_LOCK
/

drop synonym DBA_LOCKS
/

drop synonym CDB_LOCK
/

drop synonym DBA_LOCK_INTERNAL
/

drop synonym CDB_LOCK_INTERNAL
/

drop synonym DBA_DML_LOCKS
/

drop synonym CDB_DML_LOCKS
/

drop synonym DBA_DDL_LOCKS
/

drop synonym CDB_DDL_LOCKS
/

drop synonym DBA_WAITERS
/

drop synonym CDB_WAITERS
/

drop synonym DBA_BLOCKERS
/

drop synonym CDB_BLOCKERS
/

drop synonym TAB
/

drop synonym COL
/

drop synonym USER_TABLES
/

drop synonym TABS
/

drop synonym USER_OBJECT_TABLES
/

drop synonym USER_ALL_TABLES
/

drop synonym ALL_TABLES
/

drop synonym ALL_OBJECT_TABLES
/

drop synonym ALL_ALL_TABLES
/

drop synonym DBA_TABLES
/

drop synonym CDB_TABLES
/

drop synonym DBA_OBJECT_TABLES
/

drop synonym CDB_OBJECT_TABLES
/

drop synonym DBA_ALL_TABLES
/

drop synonym CDB_ALL_TABLES
/

drop synonym DATABASE_PROPERTIES
/

drop synonym CDB_PROPERTIES
/

drop synonym GLOBAL_NAME
/

drop synonym USER_CATALOG
/

drop synonym CAT
/

drop synonym ALL_CATALOG
/

drop synonym DBA_CATALOG
/

drop synonym CDB_CATALOG
/

drop synonym USER_OBJECTS
/

drop synonym OBJ
/

drop synonym USER_OBJECTS_AE
/

drop synonym ALL_OBJECTS
/

drop synonym ALL_OBJECTS_AE
/

drop synonym DBA_OBJECTS
/

drop synonym DBA_OBJECTS_AE
/

drop synonym CDB_OBJECTS
/

drop synonym CDB_OBJECTS_AE
/

drop synonym DBA_INVALID_OBJECTS
/

drop synonym CDB_INVALID_OBJECTS
/

drop synonym USER_EDITIONING_VIEWS
/

drop synonym USER_EDITIONING_VIEWS_AE
/

drop synonym ALL_EDITIONING_VIEWS
/

drop synonym ALL_EDITIONING_VIEWS_AE
/

drop synonym DBA_EDITIONING_VIEWS
/

drop synonym DBA_EDITIONING_VIEWS_AE
/

drop synonym CDB_EDITIONING_VIEWS
/

drop synonym CDB_EDITIONING_VIEWS_AE
/

drop synonym USER_EDITIONING_VIEW_COLS
/

drop synonym USER_EDITIONING_VIEW_COLS_AE
/

drop synonym ALL_EDITIONING_VIEW_COLS
/

drop synonym ALL_EDITIONING_VIEW_COLS_AE
/

drop synonym DBA_EDITIONING_VIEW_COLS
/

drop synonym DBA_EDITIONING_VIEW_COLS_AE
/

drop synonym CDB_EDITIONING_VIEW_COLS
/

drop synonym CDB_EDITIONING_VIEW_COLS_AE
/

drop synonym ALL_EDITIONS
/

drop synonym DBA_EDITIONS
/

drop synonym CDB_EDITIONS
/

drop synonym USABLE_EDITIONS
/

drop synonym ALL_EDITION_COMMENTS
/

drop synonym DBA_EDITION_COMMENTS
/

drop synonym CDB_EDITION_COMMENTS
/

drop synonym USER_EDITIONED_TYPES
/

drop synonym DBA_EDITIONED_TYPES
/

drop synonym CDB_EDITIONED_TYPES
/

drop synonym FLASHBACK_TRANSACTION_QUERY
/

drop synonym DBA_RESUMABLE
/

drop synonym CDB_RESUMABLE
/

drop synonym USER_RESUMABLE
/

drop synonym USER_INDEXES
/

drop synonym IND
/

drop synonym ALL_INDEXES
/

drop synonym DBA_INDEXES
/

drop synonym CDB_INDEXES
/

drop synonym USER_IND_COLUMNS
/

drop synonym ALL_IND_COLUMNS
/

drop synonym DBA_IND_COLUMNS
/

drop synonym CDB_IND_COLUMNS
/

drop synonym USER_IND_EXPRESSIONS
/

drop synonym ALL_IND_EXPRESSIONS
/

drop synonym DBA_IND_EXPRESSIONS
/

drop synonym CDB_IND_EXPRESSIONS
/

drop synonym INDEX_STATS
/

drop synonym INDEX_HISTOGRAM
/

drop synonym USER_JOIN_IND_COLUMNS
/

drop synonym ALL_JOIN_IND_COLUMNS
/

drop synonym DBA_JOIN_IND_COLUMNS
/

drop synonym CDB_JOIN_IND_COLUMNS
/

drop synonym USER_LOBS
/

drop synonym ALL_LOBS
/

drop synonym DBA_LOBS
/

drop synonym CDB_LOBS
/

drop synonym DBA_ROLLBACK_SEGS
/

drop synonym CDB_ROLLBACK_SEGS
/

drop synonym USER_SEQUENCES
/

drop synonym SEQ
/

drop synonym ALL_SEQUENCES
/

drop synonym DBA_SEQUENCES
/

drop synonym CDB_SEQUENCES
/

drop synonym DBA_SYNONYMS
/

drop synonym CDB_SYNONYMS
/

drop synonym SYN
/

drop synonym USER_SYNONYMS
/

drop synonym ALL_SYNONYMS
/

drop synonym DBA_CLUSTERS
/

drop synonym CDB_CLUSTERS
/

drop synonym USER_CLUSTERS
/

drop synonym CLU
/

drop synonym ALL_CLUSTERS
/

drop synonym USER_CLU_COLUMNS
/

drop synonym DBA_CLU_COLUMNS
/

drop synonym CDB_CLU_COLUMNS
/

drop synonym USER_CLUSTER_HASH_EXPRESSIONS
/

drop synonym ALL_CLUSTER_HASH_EXPRESSIONS
/

drop synonym DBA_CLUSTER_HASH_EXPRESSIONS
/

drop synonym CDB_CLUSTER_HASH_EXPRESSIONS
/

drop synonym TABLE_PRIVILEGES
/

drop synonym COLUMN_PRIVILEGES
/

drop synonym USER_COL_PRIVS
/

drop synonym ALL_COL_PRIVS
/

drop synonym DBA_COL_PRIVS
/

drop synonym CDB_COL_PRIVS
/

drop synonym USER_COL_PRIVS_MADE
/

drop synonym ALL_COL_PRIVS_MADE
/

drop synonym USER_COL_PRIVS_RECD
/

drop synonym ALL_COL_PRIVS_RECD
/

drop synonym USER_ROLE_PRIVS
/

drop synonym DBA_ROLE_PRIVS
/

drop synonym CDB_ROLE_PRIVS
/

drop synonym USER_TAB_PRIVS
/

drop synonym ALL_TAB_PRIVS
/

drop synonym DBA_TAB_PRIVS
/

drop synonym CDB_TAB_PRIVS
/

drop synonym USER_TAB_PRIVS_MADE
/

drop synonym ALL_TAB_PRIVS_MADE
/

drop synonym USER_TAB_PRIVS_RECD
/

drop synonym ALL_TAB_PRIVS_RECD
/

drop synonym USER_TAB_COMMENTS
/

drop synonym ALL_TAB_COMMENTS
/

drop synonym DBA_TAB_COMMENTS
/

drop synonym CDB_TAB_COMMENTS
/

drop synonym DBA_VIEWS
/

drop synonym DBA_VIEWS_AE
/

drop synonym CDB_VIEWS
/

drop synonym CDB_VIEWS_AE
/

drop synonym USER_VIEWS
/

drop synonym USER_VIEWS_AE
/

drop synonym ALL_VIEWS
/

drop synonym ALL_VIEWS_AE
/

drop synonym DBA_CONSTRAINTS
/

drop synonym CDB_CONSTRAINTS
/

drop synonym USER_CONSTRAINTS
/

drop synonym ALL_CONSTRAINTS
/

drop synonym USER_UNUSED_COL_TABS
/

drop synonym ALL_UNUSED_COL_TABS
/

drop synonym DBA_UNUSED_COL_TABS
/

drop synonym CDB_UNUSED_COL_TABS
/

drop synonym USER_PARTIAL_DROP_TABS
/

drop synonym ALL_PARTIAL_DROP_TABS
/

drop synonym DBA_PARTIAL_DROP_TABS
/

drop synonym CDB_PARTIAL_DROP_TABS
/

drop synonym USER_CONS_COLUMNS
/

drop synonym ALL_CONS_COLUMNS
/

drop synonym DBA_CONS_COLUMNS
/

drop synonym CDB_CONS_COLUMNS
/

drop synonym USER_LOG_GROUP_COLUMNS
/

drop synonym ALL_LOG_GROUP_COLUMNS
/

drop synonym DBA_LOG_GROUP_COLUMNS
/

drop synonym CDB_LOG_GROUP_COLUMNS
/

drop synonym USER_COL_COMMENTS
/

drop synonym ALL_COL_COMMENTS
/

drop synonym DBA_COL_COMMENTS
/

drop synonym CDB_COL_COMMENTS
/

drop synonym DBA_ENCRYPTED_COLUMNS
/

drop synonym CDB_ENCRYPTED_COLUMNS
/

drop synonym ALL_ENCRYPTED_COLUMNS
/

drop synonym USER_ENCRYPTED_COLUMNS
/

drop synonym USER_TAB_COLS
/

drop synonym ALL_TAB_COLS
/

drop synonym DBA_TAB_COLS
/

drop synonym CDB_TAB_COLS
/

drop synonym USER_TAB_COLUMNS
/

drop synonym COLS
/

drop synonym ALL_TAB_COLUMNS
/

drop synonym DBA_TAB_COLUMNS
/

drop synonym CDB_TAB_COLUMNS
/

drop synonym USER_LOG_GROUPS
/

drop synonym ALL_LOG_GROUPS
/

drop synonym DBA_LOG_GROUPS
/

drop synonym CDB_LOG_GROUPS
/

drop synonym USER_UPDATABLE_COLUMNS
/

drop synonym ALL_UPDATABLE_COLUMNS
/

drop synonym DBA_UPDATABLE_COLUMNS
/

drop synonym CDB_UPDATABLE_COLUMNS
/

drop synonym USER_TAB_IDENTITY_COLS
/

drop synonym ALL_TAB_IDENTITY_COLS
/

drop synonym DBA_TAB_IDENTITY_COLS
/

drop synonym CDB_TAB_IDENTITY_COLS
/

drop synonym DBA_PDBS
/

drop synonym CDB_PDBS
/

drop synonym DBA_PDB_HISTORY
/

drop synonym CDB_PDB_HISTORY
/

drop synonym DBA_CONTAINER_DATA
/

drop synonym CDB_CONTAINER_DATA
/

drop synonym PDB_PLUG_IN_VIOLATIONS
/

drop synonym PDB_ALERTS
/

drop synonym CDB_LOCAL_ADMIN_PRIVS
/

drop synonym DBA_PDB_SAVED_STATES
/

drop synonym CDB_PDB_SAVED_STATES
/

drop synonym DBA_LOCKDOWN_PROFILES
/

drop synonym CDB_LOCKDOWN_PROFILES
/

drop synonym DBA_PDB_SNAPSHOTS
/

drop synonym CDB_PDB_SNAPSHOTS
/

drop synonym DBA_PDB_SNAPSHOTFILE
/

drop synonym CDB_PDB_SNAPSHOTFILE
/

drop synonym DBA_CONNECTION_TESTS
/

drop synonym CDB_CONNECTION_TESTS
/

drop synonym DBA_LIBRARIES
/

drop synonym CDB_LIBRARIES
/

drop synonym USER_LIBRARIES
/

drop synonym ALL_LIBRARIES
/

drop synonym DBA_PROCEDURES
/

drop synonym CDB_PROCEDURES
/

drop synonym USER_PROCEDURES
/

drop synonym ALL_PROCEDURES
/

drop synonym ALL_STORED_SETTINGS
/

drop synonym USER_STORED_SETTINGS
/

drop synonym DBA_STORED_SETTINGS
/

drop synonym CDB_STORED_SETTINGS
/

drop synonym USER_PLSQL_OBJECT_SETTINGS
/

drop synonym ALL_PLSQL_OBJECT_SETTINGS
/

drop synonym DBA_PLSQL_OBJECT_SETTINGS
/

drop synonym CDB_PLSQL_OBJECT_SETTINGS
/

drop synonym DBA_ARGUMENTS
/

drop synonym CDB_ARGUMENTS
/

drop synonym ALL_ARGUMENTS
/

drop synonym USER_ARGUMENTS
/

drop synonym USER_ASSEMBLIES
/

drop synonym ALL_ASSEMBLIES
/

drop synonym DBA_ASSEMBLIES
/

drop synonym CDB_ASSEMBLIES
/

drop synonym USER_IDENTIFIERS
/

drop synonym ALL_IDENTIFIERS
/

drop synonym DBA_IDENTIFIERS
/

drop synonym CDB_IDENTIFIERS
/

drop synonym USER_STATEMENTS
/

drop synonym ALL_STATEMENTS
/

drop synonym DBA_STATEMENTS
/

drop synonym CDB_STATEMENTS
/

drop synonym USER_PLSQL_TYPES
/

drop synonym ALL_PLSQL_TYPES
/

drop synonym DBA_PLSQL_TYPES
/

drop synonym CDB_PLSQL_TYPES
/

drop synonym USER_PLSQL_COLL_TYPES
/

drop synonym ALL_PLSQL_COLL_TYPES
/

drop synonym DBA_PLSQL_COLL_TYPES
/

drop synonym CDB_PLSQL_COLL_TYPES
/

drop synonym USER_PLSQL_TYPE_ATTRS
/

drop synonym ALL_PLSQL_TYPE_ATTRS
/

drop synonym DBA_PLSQL_TYPE_ATTRS
/

drop synonym CDB_PLSQL_TYPE_ATTRS
/

drop synonym USER_DB_LINKS
/

drop synonym ALL_DB_LINKS
/

drop synonym DBA_DB_LINKS
/

drop synonym CDB_DB_LINKS
/

drop synonym DICTIONARY
/

drop synonym DICT
/

drop synonym DICT_COLUMNS
/

drop synonym TRUSTED_SERVERS
/

drop synonym USER_RECYCLEBIN
/

drop synonym RECYCLEBIN
/

drop synonym DBA_RECYCLEBIN
/

drop synonym CDB_RECYCLEBIN
/

drop synonym DBA_SQL_TRANSLATION_PROFILES
/

drop synonym CDB_SQL_TRANSLATION_PROFILES
/

drop synonym DBA_SQL_TRANSLATIONS
/

drop synonym CDB_SQL_TRANSLATIONS
/

drop synonym DBA_ERROR_TRANSLATIONS
/

drop synonym CDB_ERROR_TRANSLATIONS
/

drop synonym USER_SQL_TRANSLATION_PROFILES
/

drop synonym USER_SQL_TRANSLATIONS
/

drop synonym USER_ERROR_TRANSLATIONS
/

drop synonym ALL_SQL_TRANSLATION_PROFILES
/

drop synonym ALL_SQL_TRANSLATIONS
/

drop synonym ALL_ERROR_TRANSLATIONS
/

drop synonym DICTIONARY_CREDENTIALS_ENCRYPT
/

drop synonym DBA_OBJECT_USAGE
/

drop synonym CDB_OBJECT_USAGE
/

drop synonym USER_OBJECT_USAGE
/

drop synonym V$OBJECT_USAGE
/

drop synonym DBA_2PC_PENDING
/

drop synonym CDB_2PC_PENDING
/

drop synonym DBA_2PC_NEIGHBORS
/

drop synonym CDB_2PC_NEIGHBORS
/

drop synonym DBA_PROFILES
/

drop synonym CDB_PROFILES
/

drop synonym USER_RESOURCE_LIMITS
/

drop synonym USER_PASSWORD_LIMITS
/

drop synonym RESOURCE_COST
/

drop synonym USER_USERS
/

drop synonym DBA_USERS
/

drop synonym CDB_USERS
/

drop synonym ALL_USERS
/

drop synonym DBA_DIGEST_VERIFIERS
/

drop synonym CDB_DIGEST_VERIFIERS
/

drop synonym DBA_SERVICES
/

drop synonym CDB_SERVICES
/

drop synonym ALL_SERVICES
/

drop synonym AUDIT_ACTIONS
/

drop synonym ALL_DEF_AUDIT_OPTS
/

drop synonym USER_OBJ_AUDIT_OPTS
/

drop synonym DBA_OBJ_AUDIT_OPTS
/

drop synonym CDB_OBJ_AUDIT_OPTS
/

drop synonym DBA_STMT_AUDIT_OPTS
/

drop synonym CDB_STMT_AUDIT_OPTS
/

drop synonym DBA_PRIV_AUDIT_OPTS
/

drop synonym CDB_PRIV_AUDIT_OPTS
/

drop synonym DBA_AUDIT_TRAIL
/

drop synonym CDB_AUDIT_TRAIL
/

drop synonym USER_AUDIT_TRAIL
/

drop synonym DBA_AUDIT_SESSION
/

drop synonym CDB_AUDIT_SESSION
/

drop synonym USER_AUDIT_SESSION
/

drop synonym DBA_AUDIT_STATEMENT
/

drop synonym CDB_AUDIT_STATEMENT
/

drop synonym USER_AUDIT_STATEMENT
/

drop synonym DBA_AUDIT_OBJECT
/

drop synonym CDB_AUDIT_OBJECT
/

drop synonym USER_AUDIT_OBJECT
/

drop synonym DBA_AUDIT_EXISTS
/

drop synonym CDB_AUDIT_EXISTS
/

drop synonym AUDITABLE_SYSTEM_ACTIONS
/

drop synonym AUDITABLE_OBJECT_ACTIONS
/

drop synonym AUDIT_UNIFIED_POLICIES
/

drop synonym AUDIT_UNIFIED_ENABLED_POLICIES
/

drop synonym AUDIT_UNIFIED_CONTEXTS
/

drop synonym AUDIT_UNIFIED_POLICY_COMMENTS
/

drop synonym SESSION_PRIVS
/

drop synonym SESSION_ROLES
/

drop synonym ROLE_SYS_PRIVS
/

drop synonym ROLE_TAB_PRIVS
/

drop synonym ROLE_ROLE_PRIVS
/

drop synonym DBA_ROLES
/

drop synonym CDB_ROLES
/

drop synonym USER_SYS_PRIVS
/

drop synonym DBA_SYS_PRIVS
/

drop synonym CDB_SYS_PRIVS
/

drop synonym USER_PROXIES
/

drop synonym DBA_PROXIES
/

drop synonym CDB_PROXIES
/

drop synonym PROXY_USERS
/

drop synonym PROXY_ROLES
/

drop synonym PROXY_USERS_AND_ROLES
/

drop synonym DBA_CONNECT_ROLE_GRANTEES
/

drop synonym CDB_CONNECT_ROLE_GRANTEES
/

drop synonym USER_CODE_ROLE_PRIVS
/

drop synonym ALL_CODE_ROLE_PRIVS
/

drop synonym DBA_CODE_ROLE_PRIVS
/

drop synonym CDB_CODE_ROLE_PRIVS
/

drop synonym USER_TYPES
/

drop synonym ALL_TYPES
/

drop synonym DBA_TYPES
/

drop synonym CDB_TYPES
/

drop synonym USER_COLL_TYPES
/

drop synonym ALL_COLL_TYPES
/

drop synonym DBA_COLL_TYPES
/

drop synonym CDB_COLL_TYPES
/

drop synonym USER_TYPE_ATTRS
/

drop synonym ALL_TYPE_ATTRS
/

drop synonym DBA_TYPE_ATTRS
/

drop synonym CDB_TYPE_ATTRS
/

drop synonym USER_TYPE_METHODS
/

drop synonym ALL_TYPE_METHODS
/

drop synonym DBA_TYPE_METHODS
/

drop synonym CDB_TYPE_METHODS
/

drop synonym USER_METHOD_PARAMS
/

drop synonym ALL_METHOD_PARAMS
/

drop synonym DBA_METHOD_PARAMS
/

drop synonym CDB_METHOD_PARAMS
/

drop synonym USER_METHOD_RESULTS
/

drop synonym ALL_METHOD_RESULTS
/

drop synonym DBA_METHOD_RESULTS
/

drop synonym CDB_METHOD_RESULTS
/

drop synonym USER_SQLJ_TYPES
/

drop synonym ALL_SQLJ_TYPES
/

drop synonym DBA_SQLJ_TYPES
/

drop synonym CDB_SQLJ_TYPES
/

drop synonym USER_TYPE_VERSIONS
/

drop synonym ALL_TYPE_VERSIONS
/

drop synonym DBA_TYPE_VERSIONS
/

drop synonym CDB_TYPE_VERSIONS
/

drop synonym USER_PENDING_CONV_TABLES
/

drop synonym ALL_PENDING_CONV_TABLES
/

drop synonym DBA_PENDING_CONV_TABLES
/

drop synonym CDB_PENDING_CONV_TABLES
/

drop synonym USER_SQLJ_TYPE_ATTRS
/

drop synonym ALL_SQLJ_TYPE_ATTRS
/

drop synonym DBA_SQLJ_TYPE_ATTRS
/

drop synonym CDB_SQLJ_TYPE_ATTRS
/

drop synonym USER_SQLJ_TYPE_METHODS
/

drop synonym ALL_SQLJ_TYPE_METHODS
/

drop synonym DBA_SQLJ_TYPE_METHODS
/

drop synonym CDB_SQLJ_TYPE_METHODS
/

drop synonym DBA_OLDIMAGE_COLUMNS
/

drop synonym CDB_OLDIMAGE_COLUMNS
/

drop synonym USER_OLDIMAGE_COLUMNS
/

drop synonym USER_NESTED_TABLE_COLS
/

drop synonym ALL_NESTED_TABLE_COLS
/

drop synonym DBA_NESTED_TABLE_COLS
/

drop synonym CDB_NESTED_TABLE_COLS
/

drop synonym ALL_DIRECTORIES
/

drop synonym DBA_DIRECTORIES
/

drop synonym CDB_DIRECTORIES
/

drop synonym USER_REFS
/

drop synonym ALL_REFS
/

drop synonym DBA_REFS
/

drop synonym CDB_REFS
/

drop synonym USER_NESTED_TABLES
/

drop synonym ALL_NESTED_TABLES
/

drop synonym DBA_NESTED_TABLES
/

drop synonym CDB_NESTED_TABLES
/

drop synonym USER_VARRAYS
/

drop synonym ALL_VARRAYS
/

drop synonym DBA_VARRAYS
/

drop synonym CDB_VARRAYS
/

drop synonym USER_OBJ_COLATTRS
/

drop synonym ALL_OBJ_COLATTRS
/

drop synonym DBA_OBJ_COLATTRS
/

drop synonym CDB_OBJ_COLATTRS
/

drop synonym USER_CONS_OBJ_COLUMNS
/

drop synonym ALL_CONS_OBJ_COLUMNS
/

drop synonym DBA_CONS_OBJ_COLUMNS
/

drop synonym CDB_CONS_OBJ_COLUMNS
/

drop synonym DBA_OPERATORS
/

drop synonym CDB_OPERATORS
/

drop synonym ALL_OPERATORS
/

drop synonym USER_OPERATORS
/

drop synonym DBA_OPBINDINGS
/

drop synonym CDB_OPBINDINGS
/

drop synonym USER_OPBINDINGS
/

drop synonym ALL_OPBINDINGS
/

drop synonym DBA_OPANCILLARY
/

drop synonym CDB_OPANCILLARY
/

drop synonym USER_OPANCILLARY
/

drop synonym ALL_OPANCILLARY
/

drop synonym DBA_OPARGUMENTS
/

drop synonym CDB_OPARGUMENTS
/

drop synonym USER_OPARGUMENTS
/

drop synonym ALL_OPARGUMENTS
/

drop synonym DBA_OPERATOR_COMMENTS
/

drop synonym USER_OPERATOR_COMMENTS
/

drop synonym ALL_OPERATOR_COMMENTS
/

drop synonym CDB_OPERATOR_COMMENTS
/

drop synonym DBA_INDEXTYPES
/

drop synonym CDB_INDEXTYPES
/

drop synonym USER_INDEXTYPES
/

drop synonym ALL_INDEXTYPES
/

drop synonym DBA_INDEXTYPE_COMMENTS
/

drop synonym USER_INDEXTYPE_COMMENTS
/

drop synonym ALL_INDEXTYPE_COMMENTS
/

drop synonym CDB_INDEXTYPE_COMMENTS
/

drop synonym DBA_INDEXTYPE_ARRAYTYPES
/

drop synonym CDB_INDEXTYPE_ARRAYTYPES
/

drop synonym USER_INDEXTYPE_ARRAYTYPES
/

drop synonym ALL_INDEXTYPE_ARRAYTYPES
/

drop synonym DBA_INDEXTYPE_OPERATORS
/

drop synonym CDB_INDEXTYPE_OPERATORS
/

drop synonym USER_INDEXTYPE_OPERATORS
/

drop synonym ALL_INDEXTYPE_OPERATORS
/

drop synonym DBA_SECONDARY_OBJECTS
/

drop synonym CDB_SECONDARY_OBJECTS
/

drop synonym USER_SECONDARY_OBJECTS
/

drop synonym ALL_SECONDARY_OBJECTS
/

drop synonym USER_PART_TABLES
/

drop synonym ALL_PART_TABLES
/

drop synonym DBA_PART_TABLES
/

drop synonym CDB_PART_TABLES
/

drop synonym USER_PART_INDEXES
/

drop synonym ALL_PART_INDEXES
/

drop synonym DBA_PART_INDEXES
/

drop synonym CDB_PART_INDEXES
/

drop synonym USER_PART_KEY_COLUMNS
/

drop synonym ALL_PART_KEY_COLUMNS
/

drop synonym DBA_PART_KEY_COLUMNS
/

drop synonym CDB_PART_KEY_COLUMNS
/

drop synonym USER_TAB_PARTITIONS
/

drop synonym ALL_TAB_PARTITIONS
/

drop synonym DBA_TAB_PARTITIONS
/

drop synonym CDB_TAB_PARTITIONS
/

drop synonym USER_IND_PARTITIONS
/

drop synonym ALL_IND_PARTITIONS
/

drop synonym DBA_IND_PARTITIONS
/

drop synonym CDB_IND_PARTITIONS
/

drop synonym USER_TAB_SUBPARTITIONS
/

drop synonym ALL_TAB_SUBPARTITIONS
/

drop synonym DBA_TAB_SUBPARTITIONS
/

drop synonym CDB_TAB_SUBPARTITIONS
/

drop synonym USER_IND_SUBPARTITIONS
/

drop synonym ALL_IND_SUBPARTITIONS
/

drop synonym DBA_IND_SUBPARTITIONS
/

drop synonym CDB_IND_SUBPARTITIONS
/

drop synonym USER_SUBPART_KEY_COLUMNS
/

drop synonym ALL_SUBPART_KEY_COLUMNS
/

drop synonym DBA_SUBPART_KEY_COLUMNS
/

drop synonym CDB_SUBPART_KEY_COLUMNS
/

drop synonym USER_PART_LOBS
/

drop synonym ALL_PART_LOBS
/

drop synonym DBA_PART_LOBS
/

drop synonym CDB_PART_LOBS
/

drop synonym USER_LOB_PARTITIONS
/

drop synonym ALL_LOB_PARTITIONS
/

drop synonym DBA_LOB_PARTITIONS
/

drop synonym CDB_LOB_PARTITIONS
/

drop synonym USER_LOB_SUBPARTITIONS
/

drop synonym ALL_LOB_SUBPARTITIONS
/

drop synonym DBA_LOB_SUBPARTITIONS
/

drop synonym CDB_LOB_SUBPARTITIONS
/

drop synonym USER_SUBPARTITION_TEMPLATES
/

drop synonym DBA_SUBPARTITION_TEMPLATES
/

drop synonym CDB_SUBPARTITION_TEMPLATES
/

drop synonym ALL_SUBPARTITION_TEMPLATES
/

drop synonym USER_LOB_TEMPLATES
/

drop synonym DBA_LOB_TEMPLATES
/

drop synonym CDB_LOB_TEMPLATES
/

drop synonym ALL_LOB_TEMPLATES
/

drop synonym ALL_SUMDELTA
/

drop synonym ALL_SUMMAP
/

drop synonym DBA_EXP_OBJECTS
/

drop synonym CDB_EXP_OBJECTS
/

drop synonym DBA_EXP_VERSION
/

drop synonym CDB_EXP_VERSION
/

drop synonym DBA_EXP_FILES
/

drop synonym CDB_EXP_FILES
/

drop synonym USER_EXTERNAL_TABLES
/

drop synonym ALL_EXTERNAL_TABLES
/

drop synonym DBA_EXTERNAL_TABLES
/

drop synonym CDB_EXTERNAL_TABLES
/

drop synonym USER_XTERNAL_PART_TABLES
/

drop synonym ALL_XTERNAL_PART_TABLES
/

drop synonym DBA_XTERNAL_PART_TABLES
/

drop synonym CDB_XTERNAL_PART_TABLES
/

drop synonym USER_XTERNAL_TAB_PARTITIONS
/

drop synonym ALL_XTERNAL_TAB_PARTITIONS
/

drop synonym DBA_XTERNAL_TAB_PARTITIONS
/

drop synonym CDB_XTERNAL_TAB_PARTITIONS
/

drop synonym USER_XTERNAL_TAB_SUBPARTITIONS
/

drop synonym ALL_XTERNAL_TAB_SUBPARTITIONS
/

drop synonym DBA_XTERNAL_TAB_SUBPARTITIONS
/

drop synonym CDB_XTERNAL_TAB_SUBPARTITIONS
/

drop synonym USER_EXTERNAL_LOCATIONS
/

drop synonym ALL_EXTERNAL_LOCATIONS
/

drop synonym DBA_EXTERNAL_LOCATIONS
/

drop synonym CDB_EXTERNAL_LOCATIONS
/

drop synonym USER_XTERNAL_LOC_PARTITIONS
/

drop synonym ALL_XTERNAL_LOC_PARTITIONS
/

drop synonym DBA_XTERNAL_LOC_PARTITIONS
/

drop synonym CDB_XTERNAL_LOC_PARTITIONS
/

drop synonym USER_XTERNAL_LOC_SUBPARTITIONS
/

drop synonym ALL_XTERNAL_LOC_SUBPARTITIONS
/

drop synonym DBA_XTERNAL_LOC_SUBPARTITIONS
/

drop synonym CDB_XTERNAL_LOC_SUBPARTITIONS
/

drop synonym ALL_MINING_ALGORITHMS
/

drop synonym USER_MINING_MODELS
/

drop synonym ALL_MINING_MODELS
/

drop synonym DBA_MINING_MODELS
/

drop synonym CDB_MINING_MODELS
/

drop synonym USER_MINING_MODEL_ATTRIBUTES
/

drop synonym ALL_MINING_MODEL_ATTRIBUTES
/

drop synonym DBA_MINING_MODEL_ATTRIBUTES
/

drop synonym CDB_MINING_MODEL_ATTRIBUTES
/

drop synonym USER_MINING_MODEL_SETTINGS
/

drop synonym ALL_MINING_MODEL_SETTINGS
/

drop synonym DBA_MINING_MODEL_SETTINGS
/

drop synonym CDB_MINING_MODEL_SETTINGS
/

drop synonym DBA_MINING_MODEL_TABLES
/

drop synonym CDB_MINING_MODEL_TABLES
/

drop synonym USER_MINING_MODEL_VIEWS
/

drop synonym ALL_MINING_MODEL_VIEWS
/

drop synonym DBA_MINING_MODEL_VIEWS
/

drop synonym CDB_MINING_MODEL_VIEWS
/

drop synonym DM_USER_MODELS
/

drop synonym USER_MINING_MODEL_PARTITIONS
/

drop synonym ALL_MINING_MODEL_PARTITIONS
/

drop synonym DBA_MINING_MODEL_PARTITIONS
/

drop synonym CDB_MINING_MODEL_PARTITIONS
/

drop synonym USER_MINING_MODEL_XFORMS
/

drop synonym ALL_MINING_MODEL_XFORMS
/

drop synonym DBA_MINING_MODEL_XFORMS
/

drop synonym CDB_MINING_MODEL_XFORMS
/

drop synonym DBA_CLUSTERING_TABLES
/

drop synonym CDB_CLUSTERING_TABLES
/

drop synonym USER_CLUSTERING_TABLES
/

drop synonym ALL_CLUSTERING_TABLES
/

drop synonym DBA_CLUSTERING_KEYS
/

drop synonym CDB_CLUSTERING_KEYS
/

drop synonym USER_CLUSTERING_KEYS
/

drop synonym ALL_CLUSTERING_KEYS
/

drop synonym DBA_CLUSTERING_DIMENSIONS
/

drop synonym CDB_CLUSTERING_DIMENSIONS
/

drop synonym ALL_CLUSTERING_DIMENSIONS
/

drop synonym USER_CLUSTERING_DIMENSIONS
/

drop synonym DBA_CLUSTERING_JOINS
/

drop synonym CDB_CLUSTERING_JOINS
/

drop synonym ALL_CLUSTERING_JOINS
/

drop synonym USER_CLUSTERING_JOINS
/

drop synonym DBA_ATTRIBUTE_DIM_ORDER_ATTRS
/

drop synonym CDB_ATTRIBUTE_DIM_ORDER_ATTRS
/

drop synonym USER_ATTRIBUTE_DIM_ORDER_ATTRS
/

drop synonym ALL_ATTRIBUTE_DIM_ORDER_ATTRS
/

drop synonym DBA_ATTRIBUTE_DIM_CLASS
/

drop synonym CDB_ATTRIBUTE_DIM_CLASS
/

drop synonym USER_ATTRIBUTE_DIM_CLASS
/

drop synonym ALL_ATTRIBUTE_DIM_CLASS
/

drop synonym DBA_ATTRIBUTE_DIM_ATTR_CLASS
/

drop synonym CDB_ATTRIBUTE_DIM_ATTR_CLASS
/

drop synonym USER_ATTRIBUTE_DIM_ATTR_CLASS
/

drop synonym ALL_ATTRIBUTE_DIM_ATTR_CLASS
/

drop synonym DBA_ATTRIBUTE_DIM_LVL_CLASS
/

drop synonym CDB_ATTRIBUTE_DIM_LVL_CLASS
/

drop synonym USER_ATTRIBUTE_DIM_LVL_CLASS
/

drop synonym ALL_ATTRIBUTE_DIM_LVL_CLASS
/

drop synonym DBA_HIER_CLASS
/

drop synonym CDB_HIER_CLASS
/

drop synonym USER_HIER_CLASS
/

drop synonym ALL_HIER_CLASS
/

drop synonym DBA_ANALYTIC_VIEW_LEVELS
/

drop synonym CDB_ANALYTIC_VIEW_LEVELS
/

drop synonym USER_ANALYTIC_VIEW_LEVELS
/

drop synonym ALL_ANALYTIC_VIEW_LEVELS
/

drop synonym DBA_ANALYTIC_VIEW_LVLGRPS
/

drop synonym CDB_ANALYTIC_VIEW_LVLGRPS
/

drop synonym USER_ANALYTIC_VIEW_LVLGRPS
/

drop synonym ALL_ANALYTIC_VIEW_LVLGRPS
/

drop synonym DBA_ANALYTIC_VIEW_ATTR_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_ATTR_CLASS
/

drop synonym USER_ANALYTIC_VIEW_ATTR_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_ATTR_CLASS
/

drop synonym DBA_ANALYTIC_VIEW_HIER_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_HIER_CLASS
/

drop synonym USER_ANALYTIC_VIEW_HIER_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_HIER_CLASS
/

drop synonym DBA_ANALYTIC_VIEW_LEVEL_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_LEVEL_CLASS
/

drop synonym USER_ANALYTIC_VIEW_LEVEL_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_LEVEL_CLASS
/

drop synonym DBA_HIER_HIER_ATTR_CLASS
/

drop synonym CDB_HIER_HIER_ATTR_CLASS
/

drop synonym USER_HIER_HIER_ATTR_CLASS
/

drop synonym ALL_HIER_HIER_ATTR_CLASS
/

drop synonym DBA_HIER_HIER_ATTRIBUTES
/

drop synonym CDB_HIER_HIER_ATTRIBUTES
/

drop synonym USER_HIER_HIER_ATTRIBUTES
/

drop synonym ALL_HIER_HIER_ATTRIBUTES
/

drop synonym DBA_ANALYTIC_VIEW_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_CLASS
/

drop synonym USER_ANALYTIC_VIEW_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_CLASS
/

drop synonym DBA_ANALYTIC_VIEW_MEAS_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_MEAS_CLASS
/

drop synonym USER_ANALYTIC_VIEW_MEAS_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_MEAS_CLASS
/

drop synonym DBA_ANALYTIC_VIEW_DIM_CLASS
/

drop synonym CDB_ANALYTIC_VIEW_DIM_CLASS
/

drop synonym USER_ANALYTIC_VIEW_DIM_CLASS
/

drop synonym ALL_ANALYTIC_VIEW_DIM_CLASS
/

drop synonym DBA_ATTRIBUTE_DIMENSIONS
/

drop synonym CDB_ATTRIBUTE_DIMENSIONS
/

drop synonym USER_ATTRIBUTE_DIMENSIONS
/

drop synonym ALL_ATTRIBUTE_DIMENSIONS
/

drop synonym DBA_ATTRIBUTE_DIM_ATTRS
/

drop synonym CDB_ATTRIBUTE_DIM_ATTRS
/

drop synonym USER_ATTRIBUTE_DIM_ATTRS
/

drop synonym ALL_ATTRIBUTE_DIM_ATTRS
/

drop synonym DBA_ATTRIBUTE_DIM_TABLES
/

drop synonym CDB_ATTRIBUTE_DIM_TABLES
/

drop synonym USER_ATTRIBUTE_DIM_TABLES
/

drop synonym ALL_ATTRIBUTE_DIM_TABLES
/

drop synonym DBA_ATTRIBUTE_DIM_LEVELS
/

drop synonym CDB_ATTRIBUTE_DIM_LEVELS
/

drop synonym USER_ATTRIBUTE_DIM_LEVELS
/

drop synonym ALL_ATTRIBUTE_DIM_LEVELS
/

drop synonym DBA_HIERARCHIES
/

drop synonym CDB_HIERARCHIES
/

drop synonym USER_HIERARCHIES
/

drop synonym ALL_HIERARCHIES
/

drop synonym DBA_HIER_LEVELS
/

drop synonym CDB_HIER_LEVELS
/

drop synonym USER_HIER_LEVELS
/

drop synonym ALL_HIER_LEVELS
/

drop synonym DBA_HIER_LEVEL_ID_ATTRS
/

drop synonym CDB_HIER_LEVEL_ID_ATTRS
/

drop synonym USER_HIER_LEVEL_ID_ATTRS
/

drop synonym ALL_HIER_LEVEL_ID_ATTRS
/

drop synonym DBA_HIER_COLUMNS
/

drop synonym CDB_HIER_COLUMNS
/

drop synonym USER_HIER_COLUMNS
/

drop synonym ALL_HIER_COLUMNS
/

drop synonym DBA_ANALYTIC_VIEWS
/

drop synonym CDB_ANALYTIC_VIEWS
/

drop synonym USER_ANALYTIC_VIEWS
/

drop synonym ALL_ANALYTIC_VIEWS
/

drop synonym DBA_ANALYTIC_VIEW_DIMENSIONS
/

drop synonym CDB_ANALYTIC_VIEW_DIMENSIONS
/

drop synonym USER_ANALYTIC_VIEW_DIMENSIONS
/

drop synonym ALL_ANALYTIC_VIEW_DIMENSIONS
/

drop synonym DBA_ANALYTIC_VIEW_CALC_MEAS
/

drop synonym CDB_ANALYTIC_VIEW_CALC_MEAS
/

drop synonym USER_ANALYTIC_VIEW_CALC_MEAS
/

drop synonym ALL_ANALYTIC_VIEW_CALC_MEAS
/

drop synonym DBA_ANALYTIC_VIEW_BASE_MEAS
/

drop synonym CDB_ANALYTIC_VIEW_BASE_MEAS
/

drop synonym USER_ANALYTIC_VIEW_BASE_MEAS
/

drop synonym ALL_ANALYTIC_VIEW_BASE_MEAS
/

drop synonym DBA_ANALYTIC_VIEW_KEYS
/

drop synonym CDB_ANALYTIC_VIEW_KEYS
/

drop synonym USER_ANALYTIC_VIEW_KEYS
/

drop synonym ALL_ANALYTIC_VIEW_KEYS
/

drop synonym DBA_ANALYTIC_VIEW_HIERS
/

drop synonym CDB_ANALYTIC_VIEW_HIERS
/

drop synonym USER_ANALYTIC_VIEW_HIERS
/

drop synonym ALL_ANALYTIC_VIEW_HIERS
/

drop synonym DBA_ANALYTIC_VIEW_COLUMNS
/

drop synonym CDB_ANALYTIC_VIEW_COLUMNS
/

drop synonym USER_ANALYTIC_VIEW_COLUMNS
/

drop synonym ALL_ANALYTIC_VIEW_COLUMNS
/

drop synonym DBA_ATTRIBUTE_DIM_KEYS
/

drop synonym CDB_ATTRIBUTE_DIM_KEYS
/

drop synonym USER_ATTRIBUTE_DIM_KEYS
/

drop synonym ALL_ATTRIBUTE_DIM_KEYS
/

drop synonym DBA_ATTRIBUTE_DIM_LEVEL_ATTRS
/

drop synonym CDB_ATTRIBUTE_DIM_LEVEL_ATTRS
/

drop synonym USER_ATTRIBUTE_DIM_LEVEL_ATTRS
/

drop synonym ALL_ATTRIBUTE_DIM_LEVEL_ATTRS
/

drop synonym DBA_ATTRIBUTE_DIM_JOIN_PATHS
/

drop synonym CDB_ATTRIBUTE_DIM_JOIN_PATHS
/

drop synonym USER_ATTRIBUTE_DIM_JOIN_PATHS
/

drop synonym ALL_ATTRIBUTE_DIM_JOIN_PATHS
/

drop synonym DBA_HIER_JOIN_PATHS
/

drop synonym CDB_HIER_JOIN_PATHS
/

drop synonym USER_HIER_JOIN_PATHS
/

drop synonym ALL_HIER_JOIN_PATHS
/

drop synonym DBA_PRIVATE_TEMP_TABLES
/

drop synonym CDB_PRIVATE_TEMP_TABLES
/

drop synonym USER_PRIVATE_TEMP_TABLES
/

drop synonym LOADER_TAB_INFO
/

drop synonym LOADER_PART_INFO
/

drop synonym LOADER_PARAM_INFO
/

drop synonym GV$LOADPSTAT
/

drop synonym GV$LOADISTAT
/

drop synonym V$LOADPSTAT
/

drop synonym V$LOADISTAT
/

drop synonym LOADER_CONSTRAINT_INFO
/

drop synonym LOADER_TRIGGER_INFO
/

drop synonym LOADER_FILE_TS
/

drop synonym LOADER_REF_INFO
/

drop synonym LOADER_OID_INFO
/

drop synonym LOADER_DIR_OBJS
/

drop synonym DATAPUMP_DIR_OBJS
/

drop synonym LOADER_COL_INFO
/

drop synonym LOADER_COL_FLAGS
/

drop synonym LOADER_LOB_FLAGS
/

drop synonym LOADER_SKIP_UNUSABLE_INDEXES
/

drop synonym LOADER_COL_TYPE
/

drop synonym LOADER_NESTED_VARRAYS
/

drop synonym LOADER_FULL_ATTR_NAME
/

drop synonym LOADER_INTCOL_INFO
/

drop synonym LOADER_LOB_INDEX_TAB
/

drop synonym LOADER_LOB_INDEX_COL
/

drop synonym LOADER_DB_OPEN_READ_WRITE
/

drop synonym USER_SUBPART_COL_STATISTICS
/

drop synonym ALL_SUBPART_COL_STATISTICS
/

drop synonym DBA_SUBPART_COL_STATISTICS
/

drop synonym CDB_SUBPART_COL_STATISTICS
/

drop synonym DBA_ASSOCIATIONS
/

drop synonym CDB_ASSOCIATIONS
/

drop synonym USER_ASSOCIATIONS
/

drop synonym ALL_ASSOCIATIONS
/

drop synonym DBA_USTATS
/

drop synonym CDB_USTATS
/

drop synonym USER_USTATS
/

drop synonym ALL_USTATS
/

drop synonym USER_TAB_MODIFICATIONS
/

drop synonym ALL_TAB_MODIFICATIONS
/

drop synonym DBA_TAB_MODIFICATIONS
/

drop synonym CDB_TAB_MODIFICATIONS
/

drop synonym DBA_OPTSTAT_OPERATIONS
/

drop synonym CDB_OPTSTAT_OPERATIONS
/

drop synonym DBA_OPTSTAT_OPERATION_TASKS
/

drop synonym CDB_OPTSTAT_OPERATION_TASKS
/

drop synonym DBA_AUTO_STAT_EXECUTIONS
/

drop synonym CDB_AUTO_STAT_EXECUTIONS
/

drop synonym ALL_TAB_STATS_HISTORY
/

drop synonym DBA_TAB_STATS_HISTORY
/

drop synonym CDB_TAB_STATS_HISTORY
/

drop synonym USER_TAB_STATS_HISTORY
/

drop synonym ALL_TAB_STAT_PREFS
/

drop synonym DBA_TAB_STAT_PREFS
/

drop synonym CDB_TAB_STAT_PREFS
/

drop synonym USER_TAB_STAT_PREFS
/

drop synonym ALL_TAB_PENDING_STATS
/

drop synonym DBA_TAB_PENDING_STATS
/

drop synonym CDB_TAB_PENDING_STATS
/

drop synonym USER_TAB_PENDING_STATS
/

drop synonym ALL_IND_PENDING_STATS
/

drop synonym DBA_IND_PENDING_STATS
/

drop synonym CDB_IND_PENDING_STATS
/

drop synonym USER_IND_PENDING_STATS
/

drop synonym DBA_DIMENSIONS
/

drop synonym CDB_DIMENSIONS
/

drop synonym ALL_DIMENSIONS
/

drop synonym USER_DIMENSIONS
/

drop synonym DBA_DIM_LEVELS
/

drop synonym CDB_DIM_LEVELS
/

drop synonym ALL_DIM_LEVELS
/

drop synonym USER_DIM_LEVELS
/

drop synonym DBA_DIM_LEVEL_KEY
/

drop synonym CDB_DIM_LEVEL_KEY
/

drop synonym ALL_DIM_LEVEL_KEY
/

drop synonym USER_DIM_LEVEL_KEY
/

drop synonym DBA_DIM_ATTRIBUTES
/

drop synonym CDB_DIM_ATTRIBUTES
/

drop synonym ALL_DIM_ATTRIBUTES
/

drop synonym USER_DIM_ATTRIBUTES
/

drop synonym DBA_DIM_HIERARCHIES
/

drop synonym CDB_DIM_HIERARCHIES
/

drop synonym ALL_DIM_HIERARCHIES
/

drop synonym USER_DIM_HIERARCHIES
/

drop synonym DBA_DIM_CHILD_OF
/

drop synonym CDB_DIM_CHILD_OF
/

drop synonym ALL_DIM_CHILD_OF
/

drop synonym USER_DIM_CHILD_OF
/

drop synonym DBA_DIM_JOIN_KEY
/

drop synonym CDB_DIM_JOIN_KEY
/

drop synonym ALL_DIM_JOIN_KEY
/

drop synonym USER_DIM_JOIN_KEY
/

drop synonym ALL_SUMMARIES
/

drop synonym USER_SUMMARIES
/

drop synonym DBA_SUMMARIES
/

drop synonym CDB_SUMMARIES
/

drop synonym DBA_SUMMARY_AGGREGATES
/

drop synonym CDB_SUMMARY_AGGREGATES
/

drop synonym USER_SUMMARY_AGGREGATES
/

drop synonym ALL_SUMMARY_AGGREGATES
/

drop synonym ALL_SUMMARY_DETAIL_TABLES
/

drop synonym USER_SUMMARY_DETAIL_TABLES
/

drop synonym DBA_SUMMARY_DETAIL_TABLES
/

drop synonym CDB_SUMMARY_DETAIL_TABLES
/

drop synonym DBA_SUMMARY_KEYS
/

drop synonym CDB_SUMMARY_KEYS
/

drop synonym ALL_SUMMARY_KEYS
/

drop synonym USER_SUMMARY_KEYS
/

drop synonym DBA_SUMMARY_JOINS
/

drop synonym CDB_SUMMARY_JOINS
/

drop synonym ALL_SUMMARY_JOINS
/

drop synonym USER_SUMMARY_JOINS
/

drop synonym ALL_MVIEW_ANALYSIS
/

drop synonym USER_MVIEW_ANALYSIS
/

drop synonym DBA_MVIEW_ANALYSIS
/

drop synonym CDB_MVIEW_ANALYSIS
/

drop synonym DBA_MVIEW_AGGREGATES
/

drop synonym CDB_MVIEW_AGGREGATES
/

drop synonym USER_MVIEW_AGGREGATES
/

drop synonym ALL_MVIEW_AGGREGATES
/

drop synonym ALL_MVIEW_DETAIL_RELATIONS
/

drop synonym USER_MVIEW_DETAIL_RELATIONS
/

drop synonym DBA_MVIEW_DETAIL_RELATIONS
/

drop synonym CDB_MVIEW_DETAIL_RELATIONS
/

drop synonym DBA_MVIEW_KEYS
/

drop synonym CDB_MVIEW_KEYS
/

drop synonym ALL_MVIEW_KEYS
/

drop synonym USER_MVIEW_KEYS
/

drop synonym DBA_MVIEW_JOINS
/

drop synonym CDB_MVIEW_JOINS
/

drop synonym ALL_MVIEW_JOINS
/

drop synonym USER_MVIEW_JOINS
/

drop synonym DBA_MVIEW_COMMENTS
/

drop synonym CDB_MVIEW_COMMENTS
/

drop synonym ALL_MVIEW_COMMENTS
/

drop synonym USER_MVIEW_COMMENTS
/

drop synonym ALL_REFRESH_DEPENDENCIES
/

drop synonym DBA_REWRITE_EQUIVALENCES
/

drop synonym CDB_REWRITE_EQUIVALENCES
/

drop synonym ALL_REWRITE_EQUIVALENCES
/

drop synonym USER_REWRITE_EQUIVALENCES
/

drop synonym DBA_MVIEW_DETAIL_PARTITION
/

drop synonym CDB_MVIEW_DETAIL_PARTITION
/

drop synonym ALL_MVIEW_DETAIL_PARTITION
/

drop synonym USER_MVIEW_DETAIL_PARTITION
/

drop synonym DBA_MVIEW_DETAIL_SUBPARTITION
/

drop synonym CDB_MVIEW_DETAIL_SUBPARTITION
/

drop synonym ALL_MVIEW_DETAIL_SUBPARTITION
/

drop synonym USER_MVIEW_DETAIL_SUBPARTITION
/

drop synonym USER_TSTZ_TAB_COLS
/

drop synonym ALL_TSTZ_TAB_COLS
/

drop synonym DBA_TSTZ_TAB_COLS
/

drop synonym CDB_TSTZ_TAB_COLS
/

drop synonym USER_TSTZ_TABLES
/

drop synonym ALL_TSTZ_TABLES
/

drop synonym DBA_TSTZ_TABLES
/

drop synonym CDB_TSTZ_TABLES
/

drop synonym USER_ERRORS
/

drop synonym USER_ERRORS_AE
/

drop synonym ALL_ERRORS
/

drop synonym ALL_ERRORS_AE
/

drop synonym DBA_ERRORS
/

drop synonym DBA_ERRORS_AE
/

drop synonym CDB_ERRORS
/

drop synonym CDB_ERRORS_AE
/

drop synonym USER_SOURCE
/

drop synonym USER_SOURCE_AE
/

drop synonym ALL_SOURCE
/

drop synonym ALL_SOURCE_AE
/

drop synonym DBA_SOURCE
/

drop synonym DBA_SOURCE_AE
/

drop synonym CDB_SOURCE
/

drop synonym CDB_SOURCE_AE
/

drop synonym USER_TRIGGERS
/

drop synonym USER_TRIGGERS_AE
/

drop synonym ALL_TRIGGERS
/

drop synonym ALL_TRIGGERS_AE
/

drop synonym DBA_TRIGGERS
/

drop synonym DBA_TRIGGERS_AE
/

drop synonym CDB_TRIGGERS
/

drop synonym CDB_TRIGGERS_AE
/

drop synonym USER_INTERNAL_TRIGGERS
/

drop synonym ALL_INTERNAL_TRIGGERS
/

drop synonym DBA_INTERNAL_TRIGGERS
/

drop synonym CDB_INTERNAL_TRIGGERS
/

drop synonym USER_TRIGGER_COLS
/

drop synonym ALL_TRIGGER_COLS
/

drop synonym DBA_TRIGGER_COLS
/

drop synonym CDB_TRIGGER_COLS
/

drop synonym USER_DEPENDENCIES
/

drop synonym ALL_DEPENDENCIES
/

drop synonym DBA_DEPENDENCIES
/

drop synonym CDB_DEPENDENCIES
/

drop synonym PUBLIC_DEPENDENCY
/

drop synonym DBA_OBJECT_SIZE
/

drop synonym CDB_OBJECT_SIZE
/

drop synonym USER_OBJECT_SIZE
/

drop synonym DBA_TRIGGER_ORDERING
/

drop synonym CDB_TRIGGER_ORDERING
/

drop synonym ALL_TRIGGER_ORDERING
/

drop synonym USER_TRIGGER_ORDERING
/

drop synonym ORA_KGLR7_DEPENDENCIES
/

drop synonym ORA_KGLR7_IDL_UB1
/

drop synonym ORA_KGLR7_IDL_CHAR
/

drop synonym ORA_KGLR7_IDL_UB2
/

drop synonym ORA_KGLR7_IDL_SB4
/

drop synonym ORA_KGLR7_DB_LINKS
/

drop synonym UTL_IDENT
/

drop synonym DBMS_PICKLER
/

drop synonym DBMS_JAVA_TEST
/

drop synonym DBMS_SPACE_ADMIN
/

drop synonym USER_SEGMENTS
/

drop synonym DBA_SEGMENTS
/

drop synonym CDB_SEGMENTS
/

drop synonym DBA_SEGMENTS_OLD
/

drop synonym CDB_SEGMENTS_OLD
/

drop synonym USER_EXTENTS
/

drop synonym DBA_EXTENTS
/

drop synonym CDB_EXTENTS
/

drop synonym DBA_UNDO_EXTENTS
/

drop synonym CDB_UNDO_EXTENTS
/

drop synonym DBA_LMT_USED_EXTENTS
/

drop synonym CDB_LMT_USED_EXTENTS
/

drop synonym DBA_DMT_USED_EXTENTS
/

drop synonym CDB_DMT_USED_EXTENTS
/

drop synonym USER_FREE_SPACE
/

drop synonym DBA_FREE_SPACE
/

drop synonym CDB_FREE_SPACE
/

drop synonym DBA_LMT_FREE_SPACE
/

drop synonym CDB_LMT_FREE_SPACE
/

drop synonym DBA_DMT_FREE_SPACE
/

drop synonym CDB_DMT_FREE_SPACE
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP1
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP2
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP3
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP4
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP5
/

drop synonym CDB_FREE_SPACE_COALESCED_TMP6
/

drop synonym DBA_FREE_SPACE_COALESCED
/

drop synonym CDB_FREE_SPACE_COALESCED
/

drop synonym DBA_DATA_FILES
/

drop synonym CDB_DATA_FILES
/

drop synonym USER_TABLESPACES
/

drop synonym DBA_TABLESPACES
/

drop synonym CDB_TABLESPACES
/

drop synonym DBA_TEMP_FILES
/

drop synonym CDB_TEMP_FILES
/

drop synonym V$TEMP_EXTENT_MAP
/

drop synonym GV$TEMP_EXTENT_MAP
/

drop synonym V$TEMP_EXTENT_POOL
/

drop synonym GV$TEMP_EXTENT_POOL
/

drop synonym V$TEMP_SPACE_HEADER
/

drop synonym GV$TEMP_SPACE_HEADER
/

drop synonym V$FILESPACE_USAGE
/

drop synonym GV$FILESPACE_USAGE
/

drop synonym DBA_TABLESPACE_GROUPS
/

drop synonym CDB_TABLESPACE_GROUPS
/

drop synonym DBA_TABLESPACE_USAGE_METRICS
/

drop synonym CDB_TABLESPACE_USAGE_METRICS
/

drop synonym DBA_AUTO_SEGADV_CTL
/

drop synonym CDB_AUTO_SEGADV_CTL
/

drop synonym DBA_AUTO_SEGADV_SUMMARY
/

drop synonym CDB_AUTO_SEGADV_SUMMARY
/

drop synonym DBA_HEATMAP_TOP_OBJECTS
/

drop synonym CDB_HEATMAP_TOP_OBJECTS
/

drop synonym DBA_HEATMAP_TOP_TABLESPACES
/

drop synonym CDB_HEATMAP_TOP_TABLESPACES
/

drop synonym USER_TS_QUOTAS
/

drop synonym DBA_TS_QUOTAS
/

drop synonym CDB_TS_QUOTAS
/

drop synonym DBA_TEMP_FREE_SPACE
/

drop synonym CDB_TEMP_FREE_SPACE
/

drop synonym DBMS_LOB
/

drop synonym UTL_TCP
/

drop synonym UTL_HTTP
/

drop synonym DBMS_TRANSACTION_INTERNAL_SYS
/

drop synonym DBMS_SQL
/

drop synonym DBMS_OUTPUT
/

drop synonym DBMSOUTPUT_LINESARRAY
/

drop synonym DBMS_LOGSTDBY
/

drop synonym DBMS_LOGSTDBY_CONTEXT
/

drop synonym DBMS_SESSION
/

drop synonym DBMS_LOCK
/

drop synonym UTL_FILE
/

drop synonym DBMS_TYPES
/

drop synonym ANYTYPE
/

drop synonym GETANYTYPEFROMPERSISTENT
/

drop synonym ANYDATA
/

drop synonym ANYDATASET
/

drop synonym XMLTYPE
/

drop synonym XMLFORMAT
/

drop synonym XMLSEQUENCETYPE
/

drop synonym XMLSEQUENCE
/

drop synonym XQSEQUENCE
/

drop synonym SYS_XMLAGG
/

drop synonym XMLAGG
/

drop synonym SYS_IXQAGG
/

drop synonym XQWINDOWSEQUENCE
/

drop synonym SYS_IXQAGGSUM
/

drop synonym SYS_IXQAGGAVG
/

drop synonym URITYPE
/

drop synonym DBURITYPE
/

drop synonym FTPURITYPE
/

drop synonym XDBURITYPE
/

drop synonym HTTPURITYPE
/

drop synonym URIFACTORY
/

drop synonym DBMS_XMLGEN
/

drop synonym DBMS_XMLSTORE
/

drop synonym WRI$_REPT_ABSTRACT_T
/

drop synonym WRI$_REPT_SQLPI
/

drop synonym WRI$_REPT_SQLT
/

drop synonym WRI$_REPT_XPLAN
/

drop synonym WRI$_REPT_DBREPLAY
/

drop synonym WRI$_REPT_SQLMONITOR
/

drop synonym WRI$_REPT_PLAN_DIFF
/

drop synonym WRI$_REPT_SPMEVOLVE
/

drop synonym WRI$_REPT_CONFIG
/

drop synonym WRI$_REPT_STORAGE
/

drop synonym WRI$_REPT_SECURITY
/

drop synonym WRI$_REPT_MEMORY
/

drop synonym WRI$_REPT_ASH
/

drop synonym WRI$_REPT_AWRV
/

drop synonym WRI$_REPT_ADDM
/

drop synonym WRI$_REPT_RTADDM
/

drop synonym WRI$_REPT_CPADDM
/

drop synonym WRI$_REPT_PERF
/

drop synonym WRI$_REPT_SQLDETAIL
/

drop synonym WRI$_REPT_SESSION
/

drop synonym WRI$_REPT_DBHOME
/

drop synonym WRI$_REPT_OPTSTATS
/

drop synonym WRI$_REPT_ARC
/

drop synonym WRI$_REPT_EMX_PERF
/

drop synonym WRI$_REPT_TCB
/

drop synonym WRI$_REPT_CELL
/

drop synonym WRI$_REPT_STATSADV
/

drop synonym WRI$_REPT_RSRCMGR
/

drop synonym WRI$_REPT_AUTO_INDEX
/

drop synonym WRI$_REPT_ASH_OMX
/

drop synonym SQL_PLAN_ROW_TYPE
/

drop synonym SQL_PLAN_TABLE_TYPE
/

drop synonym PLAN_TABLE
/

drop synonym SQL_PLAN_STAT_ROW_TYPE
/

drop synonym SQL_PLAN_ALLSTAT_ROW_TYPE
/

drop synonym GENERIC_PLAN_OBJECT
/

drop synonym PLAN_TABLE_OBJECT
/

drop synonym CURSOR_CACHE_OBJECT
/

drop synonym AWR_OBJECT
/

drop synonym SQLSET_OBJECT
/

drop synonym SPM_OBJECT
/

drop synonym SQL_PROFILE_OBJECT
/

drop synonym ADVISOR_OBJECT
/

drop synonym PLAN_OBJECT_LIST
/

drop synonym DBMS_DBFS_CONTENT_PROPERTY_T
/

drop synonym DBMS_DBFS_CONTENT_PROPERTIES_T
/

drop synonym DBMS_DBFS_CONTENT_CONTEXT_T
/

drop synonym DBMS_DBFS_CONTENT_RAW_T
/

drop synonym DBMS_DBFS_CONTENT_LIST_ITEM_T
/

drop synonym DBMS_DBFS_CONTENT_LIST_ITEMS_T
/

drop synonym DIR_ENTRY_T
/

drop synonym DIR_ENTRIES_T
/

drop synonym DBMS_DBFS_HS_ITEM_T
/

drop synonym DBMS_DBFS_HS_LITEMS_T
/

drop synonym ROLE_ID_LIST
/

drop synonym ROLE_ARRAY
/

drop synonym ROLENAME_ARRAY
/

drop synonym GRANT_PATH
/

drop synonym ROLE_NAME_LIST
/

drop synonym PACKAGE_ARRAY
/

drop synonym ADR_HOME_T
/

drop synonym ADR_INCIDENT_T
/

drop synonym ADR_INCIDENT_ERR_ARGS_T
/

drop synonym ADR_INCIDENT_FILES_T
/

drop synonym ADR_INCIDENT_CORR_KEYS_T
/

drop synonym ADR_LOG_MSG_T
/

drop synonym ADR_LOG_MSG_ECID_T
/

drop synonym ADR_LOG_MSG_ERRID_T
/

drop synonym ADR_LOG_MSG_ARG_T
/

drop synonym ADR_LOG_MSG_ARGS_T
/

drop synonym ADR_LOG_MSG_SUPPL_ATTRS_T
/

drop synonym ADR_LOG_MSG_SUPPL_ATTR_T
/

drop synonym DS_VARRAY_4_CLOB
/

drop synonym DBMSSTATNUMTAB
/

drop synonym DBA_SENSITIVE_DATA
/

drop synonym CDB_SENSITIVE_DATA
/

drop synonym DBA_DISCOVERY_SOURCE
/

drop synonym CDB_DISCOVERY_SOURCE
/

drop synonym DBA_SENSITIVE_COLUMN_TYPES
/

drop synonym CDB_SENSITIVE_COLUMN_TYPES
/

drop synonym DBA_TSDP_POLICY_FEATURE
/

drop synonym CDB_TSDP_POLICY_FEATURE
/

drop synonym DBA_TSDP_POLICY_CONDITION
/

drop synonym CDB_TSDP_POLICY_CONDITION
/

drop synonym DBA_TSDP_POLICY_PARAMETER
/

drop synonym CDB_TSDP_POLICY_PARAMETER
/

drop synonym DBA_TSDP_POLICY_TYPE
/

drop synonym CDB_TSDP_POLICY_TYPE
/

drop synonym DBA_TSDP_POLICY_PROTECTION
/

drop synonym CDB_TSDP_POLICY_PROTECTION
/

drop synonym DBA_TSDP_IMPORT_ERRORS
/

drop synonym CDB_TSDP_IMPORT_ERRORS
/

drop synonym JSON_KEY_LIST
/

drop synonym JDOM_T
/

drop synonym JSON_ELEMENT_T
/

drop synonym JSON_OBJECT_T
/

drop synonym JSON_ARRAY_T
/

drop synonym JSON_SCALAR_T
/

drop synonym DBA_ROLLING_DATABASES
/

drop synonym CDB_ROLLING_DATABASES
/

drop synonym DBA_ROLLING_EVENTS
/

drop synonym CDB_ROLLING_EVENTS
/

drop synonym DBA_ROLLING_PARAMETERS
/

drop synonym CDB_ROLLING_PARAMETERS
/

drop synonym DBA_ROLLING_PLAN
/

drop synonym CDB_ROLLING_PLAN
/

drop synonym DBA_ROLLING_STATISTICS
/

drop synonym CDB_ROLLING_STATISTICS
/

drop synonym DBA_ROLLING_STATUS
/

drop synonym CDB_ROLLING_STATUS
/

drop synonym DBA_RSRC_PLANS
/

drop synonym CDB_RSRC_PLANS
/

drop synonym DBA_RSRC_CONSUMER_GROUPS
/

drop synonym CDB_RSRC_CONSUMER_GROUPS
/

drop synonym DBA_RSRC_CATEGORIES
/

drop synonym CDB_RSRC_CATEGORIES
/

drop synonym DBA_RSRC_PLAN_DIRECTIVES
/

drop synonym CDB_RSRC_PLAN_DIRECTIVES
/

drop synonym DBA_RSRC_CONSUMER_GROUP_PRIVS
/

drop synonym CDB_RSRC_CONSUMER_GROUP_PRIVS
/

drop synonym USER_RSRC_CONSUMER_GROUP_PRIVS
/

drop synonym DBA_RSRC_MANAGER_SYSTEM_PRIVS
/

drop synonym CDB_RSRC_MANAGER_SYSTEM_PRIVS
/

drop synonym USER_RSRC_MANAGER_SYSTEM_PRIVS
/

drop synonym DBA_RSRC_GROUP_MAPPINGS
/

drop synonym CDB_RSRC_GROUP_MAPPINGS
/

drop synonym DBA_RSRC_MAPPING_PRIORITY
/

drop synonym CDB_RSRC_MAPPING_PRIORITY
/

drop synonym DBA_RSRC_STORAGE_POOL_MAPPING
/

drop synonym CDB_RSRC_STORAGE_POOL_MAPPING
/

drop synonym DBA_RSRC_CAPABILITY
/

drop synonym CDB_RSRC_CAPABILITY
/

drop synonym DBA_RSRC_INSTANCE_CAPABILITY
/

drop synonym CDB_RSRC_INSTANCE_CAPABILITY
/

drop synonym DBA_RSRC_IO_CALIBRATE
/

drop synonym CDB_RSRC_IO_CALIBRATE
/

drop synonym DBA_CDB_RSRC_PLANS
/

drop synonym CDB_CDB_RSRC_PLANS
/

drop synonym DBA_CDB_RSRC_PLAN_DIRECTIVES
/

drop synonym CDB_CDB_RSRC_PLAN_DIRECTIVES
/

drop synonym USER_FLASHBACK_TXN_STATE
/

drop synonym USER_FLASHBACK_TXN_REPORT
/

drop synonym DBA_FLASHBACK_TXN_STATE
/

drop synonym DBA_FLASHBACK_TXN_REPORT
/

drop synonym CDB_FLASHBACK_TXN_STATE
/

drop synonym CDB_FLASHBACK_TXN_REPORT
/

drop synonym V$CONTEXT
/

drop synonym GV$CONTEXT
/

drop synonym SESSION_CONTEXT
/

drop synonym ALL_CONTEXT
/

drop synonym DBA_CONTEXT
/

drop synonym CDB_CONTEXT
/

drop synonym V$GLOBALCONTEXT
/

drop synonym GV$GLOBALCONTEXT
/

drop synonym GLOBAL_CONTEXT
/

drop synonym DBA_GLOBAL_CONTEXT
/

drop synonym CDB_GLOBAL_CONTEXT
/

drop synonym DBA_ANALYZE_OBJECTS
/

drop synonym CDB_ANALYZE_OBJECTS
/

drop synonym SM$VERSION
/

drop synonym CDB_TRANSFORMATIONS
/

drop synonym CDB_ATTRIBUTE_TRANSFORMATIONS
/

drop synonym DBA_TRANSFORMATIONS
/

drop synonym USER_TRANSFORMATIONS
/

drop synonym ALL_TRANSFORMATIONS
/

drop synonym DBA_ATTRIBUTE_TRANSFORMATIONS
/

drop synonym USER_ATTRIBUTE_TRANSFORMATIONS
/

drop synonym ALL_ATTRIBUTE_TRANSFORMATIONS
/

drop synonym USER_RULE_SETS
/

drop synonym ALL_RULE_SETS
/

drop synonym DBA_RULE_SETS
/

drop synonym CDB_RULE_SETS
/

drop synonym USER_RULESETS
/

drop synonym ALL_RULESETS
/

drop synonym DBA_RULESETS
/

drop synonym CDB_RULESETS
/

drop synonym USER_RULES
/

drop synonym ALL_RULES
/

drop synonym DBA_RULES
/

drop synonym CDB_RULES
/

drop synonym USER_RULE_SET_RULES
/

drop synonym ALL_RULE_SET_RULES
/

drop synonym DBA_RULE_SET_RULES
/

drop synonym CDB_RULE_SET_RULES
/

drop synonym USER_EVALUATION_CONTEXTS
/

drop synonym ALL_EVALUATION_CONTEXTS
/

drop synonym DBA_EVALUATION_CONTEXTS
/

drop synonym CDB_EVALUATION_CONTEXTS
/

drop synonym USER_EVALUATION_CONTEXT_TABLES
/

drop synonym ALL_EVALUATION_CONTEXT_TABLES
/

drop synonym DBA_EVALUATION_CONTEXT_TABLES
/

drop synonym CDB_EVALUATION_CONTEXT_TABLES
/

drop synonym USER_EVALUATION_CONTEXT_VARS
/

drop synonym ALL_EVALUATION_CONTEXT_VARS
/

drop synonym DBA_EVALUATION_CONTEXT_VARS
/

drop synonym CDB_EVALUATION_CONTEXT_VARS
/

drop synonym RULE_EXPRESSION
/

drop synonym RULE_EXPRESSION_CLAUSES
/

drop synonym RULE_EXPRESSION_CONDITIONS
/

drop synonym DBA_POLICIES
/

drop synonym CDB_POLICIES
/

drop synonym ALL_POLICIES
/

drop synonym USER_POLICIES
/

drop synonym DBA_POLICY_GROUPS
/

drop synonym CDB_POLICY_GROUPS
/

drop synonym ALL_POLICY_GROUPS
/

drop synonym USER_POLICY_GROUPS
/

drop synonym DBA_POLICY_CONTEXTS
/

drop synonym CDB_POLICY_CONTEXTS
/

drop synonym ALL_POLICY_CONTEXTS
/

drop synonym USER_POLICY_CONTEXTS
/

drop synonym DBA_SEC_RELEVANT_COLS
/

drop synonym CDB_SEC_RELEVANT_COLS
/

drop synonym ALL_SEC_RELEVANT_COLS
/

drop synonym USER_SEC_RELEVANT_COLS
/

drop synonym DBA_POLICY_ATTRIBUTES
/

drop synonym CDB_POLICY_ATTRIBUTES
/

drop synonym ALL_POLICY_ATTRIBUTES
/

drop synonym USER_POLICY_ATTRIBUTES
/

drop synonym DBA_APPLICATION_ROLES
/

drop synonym CDB_APPLICATION_ROLES
/

drop synonym USER_APPLICATION_ROLES
/

drop synonym DBA_AUDIT_POLICIES
/

drop synonym CDB_AUDIT_POLICIES
/

drop synonym DBA_AUDIT_POLICY_COLUMNS
/

drop synonym ALL_AUDIT_POLICIES
/

drop synonym CDB_AUDIT_POLICY_COLUMNS
/

drop synonym ALL_AUDIT_POLICY_COLUMNS
/

drop synonym USER_AUDIT_POLICIES
/

drop synonym USER_AUDIT_POLICY_COLUMNS
/

drop synonym DBA_FGA_AUDIT_TRAIL
/

drop synonym CDB_FGA_AUDIT_TRAIL
/

drop synonym DBA_COMMON_AUDIT_TRAIL
/

drop synonym CDB_COMMON_AUDIT_TRAIL
/

drop synonym DBA_AUDIT_MGMT_CONFIG_PARAMS
/

drop synonym CDB_AUDIT_MGMT_CONFIG_PARAMS
/

drop synonym DBA_AUDIT_MGMT_LAST_ARCH_TS
/

drop synonym CDB_AUDIT_MGMT_LAST_ARCH_TS
/

drop synonym DBA_AUDIT_MGMT_CLEANUP_JOBS
/

drop synonym CDB_AUDIT_MGMT_CLEANUP_JOBS
/

drop synonym DBA_AUDIT_MGMT_CLEAN_EVENTS
/

drop synonym CDB_AUDIT_MGMT_CLEAN_EVENTS
/

drop synonym UTL_ALL_IND_COMPS
/

drop synonym DBA_TSM_SOURCE
/

drop synonym CDB_TSM_SOURCE
/

drop synonym DBA_TSM_DESTINATION
/

drop synonym CDB_TSM_DESTINATION
/

drop synonym DBA_TSM_HISTORY
/

drop synonym CDB_TSM_HISTORY
/

drop synonym CQ_NOTIFICATION$_REG_INFO
/

drop synonym CQ_NOTIFICATION$_ROW
/

drop synonym CQ_NOTIFICATION$_ROW_ARRAY
/

drop synonym CQ_NOTIFICATION$_TABLE
/

drop synonym CQ_NOTIFICATION$_TABLE_ARRAY
/

drop synonym CQ_NOTIFICATION$_QUERY
/

drop synonym CQ_NOTIFICATION$_QUERY_ARRAY
/

drop synonym CQ_NOTIFICATION$_DESCRIPTOR
/

drop synonym DBA_CHANGE_NOTIFICATION_REGS
/

drop synonym CDB_CHANGE_NOTIFICATION_REGS
/

drop synonym USER_CHANGE_NOTIFICATION_REGS
/

drop synonym DBA_CQ_NOTIFICATION_QUERIES
/

drop synonym CDB_CQ_NOTIFICATION_QUERIES
/

drop synonym USER_CQ_NOTIFICATION_QUERIES
/

drop synonym ORA_MINING_NUMBER_NT
/

drop synonym ORA_MINING_VARCHAR2_NT
/

drop synonym ORA_MINING_TABLE_TYPE
/

drop synonym ORA_MINING_TABLES_NT
/

drop synonym DM_MODEL_SIGNATURE_ATTRIBUTE
/

drop synonym DM_MODEL_SIGNATURE
/

drop synonym DM_MODEL_SETTING
/

drop synonym DM_MODEL_SETTINGS
/

drop synonym DM_PREDICATE
/

drop synonym DM_PREDICATES
/

drop synonym DM_RULE
/

drop synonym DM_RULES
/

drop synonym DM_ITEM
/

drop synonym DM_ITEMS
/

drop synonym DM_ITEMSET
/

drop synonym DM_ITEMSETS
/

drop synonym DM_CENTROID
/

drop synonym DM_CENTROIDS
/

drop synonym DM_HISTOGRAM_BIN
/

drop synonym DM_HISTOGRAMS
/

drop synonym DM_CHILD
/

drop synonym DM_CHILDREN
/

drop synonym DM_CLUSTER
/

drop synonym DM_CLUSTERS
/

drop synonym DM_CONDITIONAL
/

drop synonym DM_CONDITIONALS
/

drop synonym DM_NB_DETAIL
/

drop synonym DM_NB_DETAILS
/

drop synonym DM_NMF_ATTRIBUTE
/

drop synonym DM_NMF_ATTRIBUTE_SET
/

drop synonym DM_NMF_FEATURE
/

drop synonym DM_NMF_FEATURE_SET
/

drop synonym DM_SVM_ATTRIBUTE
/

drop synonym DM_SVM_ATTRIBUTE_SET
/

drop synonym DM_SVM_LINEAR_COEFF
/

drop synonym DM_SVM_LINEAR_COEFF_SET
/

drop synonym DM_GLM_COEFF
/

drop synonym DM_GLM_COEFF_SET
/

drop synonym DM_SVD_MATRIX
/

drop synonym DM_SVD_MATRIX_SET
/

drop synonym DM_MODEL_GLOBAL_DETAIL
/

drop synonym DM_MODEL_GLOBAL_DETAILS
/

drop synonym DM_NESTED_NUMERICAL
/

drop synonym DM_NESTED_NUMERICALS
/

drop synonym DM_NESTED_CATEGORICAL
/

drop synonym DM_NESTED_CATEGORICALS
/

drop synonym DM_RANKED_ATTRIBUTE
/

drop synonym DM_RANKED_ATTRIBUTES
/

drop synonym DM_TRANSFORM
/

drop synonym DM_TRANSFORMS
/

drop synonym DM_COST_ELEMENT
/

drop synonym DM_COST_MATRIX
/

drop synonym DM_NESTED_BINARY_FLOAT
/

drop synonym DM_NESTED_BINARY_FLOATS
/

drop synonym DM_NESTED_BINARY_DOUBLE
/

drop synonym DM_NESTED_BINARY_DOUBLES
/

drop synonym DM_EM_COMPONENT
/

drop synonym DM_EM_COMPONENT_SET
/

drop synonym DM_EM_PROJECTION
/

drop synonym DM_EM_PROJECTION_SET
/

drop synonym DM_MODEL_TEXT_DF
/

drop synonym DM_MODEL_TEXT_DFS
/

drop synonym DBA_CPOOL_INFO
/

drop synonym CDB_CPOOL_INFO
/

drop synonym DBA_SSCR_CAPTURE
/

drop synonym CDB_SSCR_CAPTURE
/

drop synonym DBA_SSCR_RESTORE
/

drop synonym CDB_SSCR_RESTORE
/

drop synonym DBA_SUBSCR_REGISTRATIONS
/

drop synonym CDB_SUBSCR_REGISTRATIONS
/

drop synonym USER_SUBSCR_REGISTRATIONS
/

drop synonym DBA_QUEUE_TABLES
/

drop synonym CDB_QUEUE_TABLES
/

drop synonym ALL_QUEUE_TABLES
/

drop synonym USER_QUEUE_TABLES
/

drop synonym DBA_QUEUES
/

drop synonym CDB_QUEUES
/

drop synonym ALL_QUEUES
/

drop synonym ALL_DEQUEUE_QUEUES
/

drop synonym ALL_INT_DEQUEUE_QUEUES
/

drop synonym USER_QUEUES
/

drop synonym DBA_QUEUE_PUBLISHERS
/

drop synonym CDB_QUEUE_PUBLISHERS
/

drop synonym ALL_QUEUE_PUBLISHERS
/

drop synonym USER_QUEUE_PUBLISHERS
/

drop synonym QUEUE_PRIVILEGES
/

drop synonym V$AQ
/

drop synonym GV$AQ
/

drop synonym AQ$INTERNET_USERS
/

drop synonym DBA_AQ_AGENTS
/

drop synonym CDB_AQ_AGENTS
/

drop synonym DBA_AQ_AGENT_PRIVS
/

drop synonym CDB_AQ_AGENT_PRIVS
/

drop synonym USER_AQ_AGENT_PRIVS
/

drop synonym AQ$_UNFLUSHED_DEQUEUES
/

drop synonym DBA_RESOURCE_INCARNATIONS
/

drop synonym CDB_RESOURCE_INCARNATIONS
/

drop synonym USER_OUTLINES
/

drop synonym ALL_OUTLINES
/

drop synonym DBA_OUTLINES
/

drop synonym CDB_OUTLINES
/

drop synonym USER_OUTLINE_HINTS
/

drop synonym ALL_OUTLINE_HINTS
/

drop synonym DBA_OUTLINE_HINTS
/

drop synonym CDB_OUTLINE_HINTS
/

drop synonym OL$
/

drop synonym OL$HINTS
/

drop synonym OL$NODES
/

drop synonym V$DATAPUMP_JOB
/

drop synonym V$DATAPUMP_SESSION
/

drop synonym GV$DATAPUMP_JOB
/

drop synonym GV$DATAPUMP_SESSION
/

drop synonym DBA_DATAPUMP_JOBS
/

drop synonym USER_DATAPUMP_JOBS
/

drop synonym CDB_DATAPUMP_JOBS
/

drop synonym DBA_DATAPUMP_SESSIONS
/

drop synonym CDB_DATAPUMP_SESSIONS
/

drop synonym CLIENT_RESULT_CACHE_STATS$
/

drop synonym DBMS_REGISTRY
/

drop synonym DBA_REGISTRY
/

drop synonym CDB_REGISTRY
/

drop synonym DBA_SERVER_REGISTRY
/

drop synonym CDB_SERVER_REGISTRY
/

drop synonym USER_REGISTRY
/

drop synonym DBA_REGISTRY_HIERARCHY
/

drop synonym CDB_REGISTRY_HIERARCHY
/

drop synonym ALL_REGISTRY_BANNERS
/

drop synonym DBA_REGISTRY_LOG
/

drop synonym CDB_REGISTRY_LOG
/

drop synonym DBA_REGISTRY_HISTORY
/

drop synonym CDB_REGISTRY_HISTORY
/

drop synonym DBA_REGISTRY_PROGRESS
/

drop synonym CDB_REGISTRY_PROGRESS
/

drop synonym DBA_REGISTRY_DEPENDENCIES
/

drop synonym CDB_REGISTRY_DEPENDENCIES
/

drop synonym DBA_REGISTRY_DATABASE
/

drop synonym CDB_REGISTRY_DATABASE
/

drop synonym DBA_REGISTRY_ERROR
/

drop synonym CDB_REGISTRY_ERROR
/

drop synonym DBA_REGISTRY_SCHEMAS
/

drop synonym CDB_REGISTRY_SCHEMAS
/

drop synonym DBA_REGISTRY_BACKPORTS
/

drop synonym CDB_REGISTRY_BACKPORTS
/

drop synonym DBMS_UTILITY
/

drop synonym DBA_FEATURE_USAGE_STATISTICS
/

drop synonym CDB_FEATURE_USAGE_STATISTICS
/

drop synonym DBA_HIGH_WATER_MARK_STATISTICS
/

drop synonym CDB_HIGH_WATER_MARK_STATISTICS
/

drop synonym DBA_CPU_USAGE_STATISTICS
/

drop synonym CDB_CPU_USAGE_STATISTICS
/

drop synonym V$ALERT_TYPES
/

drop synonym GV$ALERT_TYPES
/

drop synonym V$THRESHOLD_TYPES
/

drop synonym GV$THRESHOLD_TYPES
/

drop synonym DBA_ALERT_ARGUMENTS
/

drop synonym CDB_ALERT_ARGUMENTS
/

drop synonym DBA_AUTOTASK_SCHEDULE_CONTROL
/

drop synonym CDB_AUTOTASK_SCHEDULE_CONTROL
/

drop synonym DBA_ENABLED_TRACES
/

drop synonym CDB_ENABLED_TRACES
/

drop synonym DBA_ENABLED_AGGREGATIONS
/

drop synonym CDB_ENABLED_AGGREGATIONS
/

drop synonym V$CLIENT_STATS
/

drop synonym GV$CLIENT_STATS
/

drop synonym V$SERV_MOD_ACT_STATS
/

drop synonym GV$SERV_MOD_ACT_STATS
/

drop synonym V$SERVICE_STATS
/

drop synonym GV$SERVICE_STATS
/

drop synonym V$SYS_TIME_MODEL
/

drop synonym GV$SYS_TIME_MODEL
/

drop synonym V$SESS_TIME_MODEL
/

drop synonym GV$SESS_TIME_MODEL
/

drop synonym SQL_BINDS
/

drop synonym SQL_BIND
/

drop synonym SQL_BIND_SET
/

drop synonym SQL_OBJECTS
/

drop synonym SQLSET_ROW
/

drop synonym SQLSET
/

drop synonym SQLPROF_ATTR
/

drop synonym DBA_UMF_TOPOLOGY
/

drop synonym DBA_UMF_REGISTRATION
/

drop synonym DBA_UMF_LINK
/

drop synonym DBA_UMF_SERVICE
/

drop synonym DBA_SQL_PROFILES
/

drop synonym CDB_SQL_PROFILES
/

drop synonym DBA_SQL_PLAN_BASELINES
/

drop synonym CDB_SQL_PLAN_BASELINES
/

drop synonym DBA_SQL_MANAGEMENT_CONFIG
/

drop synonym CDB_SQL_MANAGEMENT_CONFIG
/

drop synonym DBA_SQL_PATCHES
/

drop synonym CDB_SQL_PATCHES
/

drop synonym DBA_SQL_QUARANTINE
/

drop synonym CDB_SQL_QUARANTINE
/

drop synonym DBA_LOGMNR_LOG
/

drop synonym CDB_LOGMNR_LOG
/

drop synonym DBA_LOGMNR_SESSION
/

drop synonym CDB_LOGMNR_SESSION
/

drop synonym DBA_LOGMNR_PROFILE_TABLE_STATS
/

drop synonym CDB_LOGMNR_PROFILE_TABLE_STATS
/

drop synonym DBA_LOGMNR_PROFILE_PLSQL_STATS
/

drop synonym CDB_LOGMNR_PROFILE_PLSQL_STATS
/

drop synonym DBA_SUPPLEMENTAL_LOGGING
/

drop synonym CDB_SUPPLEMENTAL_LOGGING
/

drop synonym DBA_USERS_WITH_DEFPWD
/

drop synonym CDB_USERS_WITH_DEFPWD
/

drop synonym V$DIAG_ADR_CONTROL
/

drop synonym V$DIAG_ADR_INVALIDATION
/

drop synonym V$DIAG_INCIDENT
/

drop synonym V$DIAG_PROBLEM
/

drop synonym V$DIAG_INCCKEY
/

drop synonym V$DIAG_INCIDENT_FILE
/

drop synonym V$DIAG_SWEEPERR
/

drop synonym V$DIAG_PICKLEERR
/

drop synonym V$DIAG_VIEW
/

drop synonym V$DIAG_VIEWCOL
/

drop synonym V$DIAG_HM_RUN
/

drop synonym V$DIAG_HM_FINDING
/

drop synonym V$DIAG_HM_RECOMMENDATION
/

drop synonym V$DIAG_HM_FDG_SET
/

drop synonym V$DIAG_HM_INFO
/

drop synonym V$DIAG_HM_MESSAGE
/

drop synonym V$DIAG_DDE_USER_ACTION_DEF
/

drop synonym V$DIAG_DDE_USR_ACT_PARAM_DEF
/

drop synonym V$DIAG_DDE_USER_ACTION
/

drop synonym V$DIAG_DDE_USR_ACT_PARAM
/

drop synonym V$DIAG_DDE_USR_INC_TYPE
/

drop synonym V$DIAG_DDE_USR_INC_ACT_MAP
/

drop synonym V$DIAG_IPS_PACKAGE
/

drop synonym V$DIAG_IPS_PACKAGE_INCIDENT
/

drop synonym V$DIAG_IPS_PACKAGE_FILE
/

drop synonym V$DIAG_IPS_FILE_METADATA
/

drop synonym V$DIAG_IPS_FILE_COPY_LOG
/

drop synonym V$DIAG_IPS_PACKAGE_HISTORY
/

drop synonym V$DIAG_IPS_PKG_UNPACK_HIST
/

drop synonym V$DIAG_IPS_REMOTE_PACKAGE
/

drop synonym V$DIAG_IPS_CONFIGURATION
/

drop synonym V$DIAG_IPS_PROGRESS_LOG
/

drop synonym V$DIAG_INC_METER_SUMMARY
/

drop synonym V$DIAG_INC_METER_INFO
/

drop synonym V$DIAG_INC_METER_CONFIG
/

drop synonym V$DIAG_INC_METER_IMPT_DEF
/

drop synonym V$DIAG_INC_METER_PK_IMPTS
/

drop synonym V$DIAG_DIR_EXT
/

drop synonym V$DIAG_LOG_EXT
/

drop synonym V$DIAG_ALERT_EXT
/

drop synonym V$DIAG_RELMD_EXT
/

drop synonym V$DIAG_EM_USER_ACTIVITY
/

drop synonym V$DIAG_EM_DIAG_JOB
/

drop synonym V$DIAG_EM_TARGET_INFO
/

drop synonym V$DIAG_AMS_XACTION
/

drop synonym V$DIAG_DFW_CONFIG_CAPTURE
/

drop synonym V$DIAG_DFW_CONFIG_ITEM
/

drop synonym V$DIAG_DFW_PATCH_CAPTURE
/

drop synonym V$DIAG_DFW_PATCH_ITEM
/

drop synonym V$DIAG_DFW_PURGE
/

drop synonym V$DIAG_DFW_PURGE_ITEM
/

drop synonym V$DIAG_ADR_CONTROL_AUX
/

drop synonym V$DIAG_PDB_PROBLEM
/

drop synonym V$DIAG_PDB_SPACE_MGMT
/

drop synonym V$DIAG_VSHOWINCB
/

drop synonym V$DIAG_VSHOWINCB_I
/

drop synonym V$DIAG_V_INCFCOUNT
/

drop synonym V$DIAG_V_NFCINC
/

drop synonym V$DIAG_VSHOWCATVIEW
/

drop synonym V$DIAG_VINCIDENT
/

drop synonym V$DIAG_VINC_METER_INFO
/

drop synonym V$DIAG_VIPS_FILE_METADATA
/

drop synonym V$DIAG_VIPS_PKG_FILE
/

drop synonym V$DIAG_VIPS_PACKAGE_FILE
/

drop synonym V$DIAG_VIPS_PACKAGE_HISTORY
/

drop synonym V$DIAG_VIPS_FILE_COPY_LOG
/

drop synonym V$DIAG_VIPS_PACKAGE_SIZE
/

drop synonym V$DIAG_VIPS_PKG_INC_DTL1
/

drop synonym V$DIAG_VIPS_PKG_INC_DTL
/

drop synonym V$DIAG_VINCIDENT_FILE
/

drop synonym V$DIAG_V_INCCOUNT
/

drop synonym V$DIAG_V_IPSPRBCNT1
/

drop synonym V$DIAG_V_IPSPRBCNT
/

drop synonym V$DIAG_VPROBLEM_LASTINC
/

drop synonym V$DIAG_VPROBLEM_INT
/

drop synonym V$DIAG_VEM_USER_ACTLOG
/

drop synonym V$DIAG_VEM_USER_ACTLOG1
/

drop synonym V$DIAG_VPROBLEM1
/

drop synonym V$DIAG_VPROBLEM2
/

drop synonym V$DIAG_V_INC_METER_INFO_PROB
/

drop synonym V$DIAG_VPROBLEM
/

drop synonym V$DIAG_VPROBLEM_BUCKET1
/

drop synonym V$DIAG_VPROBLEM_BUCKET
/

drop synonym V$DIAG_VPROBLEM_BUCKET_COUNT
/

drop synonym V$DIAG_VHM_RUN
/

drop synonym V$DIAG_DIAGV_INCIDENT
/

drop synonym V$DIAG_VIPS_PACKAGE_MAIN_INT
/

drop synonym V$DIAG_VIPS_PKG_MAIN_PROBLEM
/

drop synonym V$DIAG_V_ACTINC
/

drop synonym V$DIAG_V_ACTPROB
/

drop synonym V$DIAG_V_SWPERRCOUNT
/

drop synonym V$DIAG_VIPS_PKG_INC_CAND
/

drop synonym V$DIAG_VNOT_EXIST_INCIDENT
/

drop synonym V$DIAG_VPDB_PROBLEM
/

drop synonym V$DIAG_VTEST_EXISTS
/

drop synonym V$DIAG_VADR_CONTROL
/

drop synonym REPORT_COMPONENTS
/

drop synonym REPORT_FORMATS
/

drop synonym DBA_HIST_REPORTS
/

drop synonym CDB_HIST_REPORTS
/

drop synonym DBA_HIST_REPORTS_DETAILS
/

drop synonym CDB_HIST_REPORTS_DETAILS
/

drop synonym DBA_HIST_REPORTS_TIMEBANDS
/

drop synonym CDB_HIST_REPORTS_TIMEBANDS
/

drop synonym DBA_HIST_REPORTS_CONTROL
/

drop synonym CDB_HIST_REPORTS_CONTROL
/

drop synonym "_REPORT_COMPONENT_OBJECTS"
/

drop synonym "_REPORT_FORMATS"
/

drop synonym DBA_DBFS_HS
/

drop synonym CDB_DBFS_HS
/

drop synonym USER_DBFS_HS
/

drop synonym DBA_DBFS_HS_PROPERTIES
/

drop synonym CDB_DBFS_HS_PROPERTIES
/

drop synonym USER_DBFS_HS_PROPERTIES
/

drop synonym DBA_DBFS_HS_COMMANDS
/

drop synonym CDB_DBFS_HS_COMMANDS
/

drop synonym USER_DBFS_HS_COMMANDS
/

drop synonym DBA_DBFS_HS_FIXED_PROPERTIES
/

drop synonym CDB_DBFS_HS_FIXED_PROPERTIES
/

drop synonym USER_DBFS_HS_FIXED_PROPERTIES
/

drop synonym XS$CACHE_ACTIONS
/

drop synonym XS$CACHE_DELETE
/

drop synonym DBA_XS_OBJECTS
/

drop synonym CDB_XS_OBJECTS
/

drop synonym DBA_XS_PRINCIPALS
/

drop synonym CDB_XS_PRINCIPALS
/

drop synonym DBA_XS_USERS
/

drop synonym CDB_XS_USERS
/

drop synonym USER_XS_USERS
/

drop synonym USER_XS_PASSWORD_LIMITS
/

drop synonym DBA_XS_ROLES
/

drop synonym CDB_XS_ROLES
/

drop synonym DBA_XS_DYNAMIC_ROLES
/

drop synonym CDB_XS_DYNAMIC_ROLES
/

drop synonym DBA_XS_EXTERNAL_PRINCIPALS
/

drop synonym CDB_XS_EXTERNAL_PRINCIPALS
/

drop synonym DBA_XS_ROLE_GRANTS
/

drop synonym CDB_XS_ROLE_GRANTS
/

drop synonym DBA_XS_PROXY_ROLES
/

drop synonym CDB_XS_PROXY_ROLES
/

drop synonym DBA_XS_NS_TEMPLATES
/

drop synonym CDB_XS_NS_TEMPLATES
/

drop synonym DBA_XS_NS_TEMPLATE_ATTRIBUTES
/

drop synonym CDB_XS_NS_TEMPLATE_ATTRIBUTES
/

drop synonym DBA_XS_SECURITY_CLASSES
/

drop synonym CDB_XS_SECURITY_CLASSES
/

drop synonym ALL_XS_SECURITY_CLASSES
/

drop synonym USER_XS_SECURITY_CLASSES
/

drop synonym DBA_XS_SECURITY_CLASS_DEP
/

drop synonym CDB_XS_SECURITY_CLASS_DEP
/

drop synonym ALL_XS_SECURITY_CLASS_DEP
/

drop synonym USER_XS_SECURITY_CLASS_DEP
/

drop synonym DBA_XS_PRIVILEGES
/

drop synonym CDB_XS_PRIVILEGES
/

drop synonym ALL_XS_PRIVILEGES
/

drop synonym USER_XS_PRIVILEGES
/

drop synonym DBA_XS_IMPLIED_PRIVILEGES
/

drop synonym CDB_XS_IMPLIED_PRIVILEGES
/

drop synonym ALL_XS_IMPLIED_PRIVILEGES
/

drop synonym USER_XS_IMPLIED_PRIVILEGES
/

drop synonym DBA_XS_ACLS
/

drop synonym CDB_XS_ACLS
/

drop synonym ALL_XS_ACLS
/

drop synonym USER_XS_ACLS
/

drop synonym DBA_XS_ACES
/

drop synonym CDB_XS_ACES
/

drop synonym ALL_XS_ACES
/

drop synonym USER_XS_ACES
/

drop synonym DBA_XS_POLICIES
/

drop synonym CDB_XS_POLICIES
/

drop synonym ALL_XS_POLICIES
/

drop synonym USER_XS_POLICIES
/

drop synonym DBA_XS_REALM_CONSTRAINTS
/

drop synonym CDB_XS_REALM_CONSTRAINTS
/

drop synonym ALL_XS_REALM_CONSTRAINTS
/

drop synonym USER_XS_REALM_CONSTRAINTS
/

drop synonym DBA_XS_INHERITED_REALMS
/

drop synonym CDB_XS_INHERITED_REALMS
/

drop synonym ALL_XS_INHERITED_REALMS
/

drop synonym USER_XS_INHERITED_REALMS
/

drop synonym DBA_XS_ACL_PARAMETERS
/

drop synonym CDB_XS_ACL_PARAMETERS
/

drop synonym ALL_XS_ACL_PARAMETERS
/

drop synonym USER_XS_ACL_PARAMETERS
/

drop synonym DBA_XS_COLUMN_CONSTRAINTS
/

drop synonym CDB_XS_COLUMN_CONSTRAINTS
/

drop synonym ALL_XS_COLUMN_CONSTRAINTS
/

drop synonym USER_XS_COLUMN_CONSTRAINTS
/

drop synonym DBA_XS_APPLIED_POLICIES
/

drop synonym CDB_XS_APPLIED_POLICIES
/

drop synonym ALL_XS_APPLIED_POLICIES
/

drop synonym CDB_XS_MODIFIED_POLICIES
/

drop synonym DBA_XS_SESSIONS
/

drop synonym CDB_XS_SESSIONS
/

drop synonym DBA_XS_ACTIVE_SESSIONS
/

drop synonym CDB_XS_ACTIVE_SESSIONS
/

drop synonym DBA_XS_SESSION_ROLES
/

drop synonym CDB_XS_SESSION_ROLES
/

drop synonym DBA_XS_SESSION_NS_ATTRIBUTES
/

drop synonym CDB_XS_SESSION_NS_ATTRIBUTES
/

drop synonym DBA_XS_AUDIT_POLICY_OPTIONS
/

drop synonym CDB_XS_AUDIT_POLICY_OPTIONS
/

drop synonym DBA_XS_ENB_AUDIT_POLICIES
/

drop synonym DBA_XS_ENABLED_AUDIT_POLICIES
/

drop synonym CDB_XS_ENB_AUDIT_POLICIES
/

drop synonym CDB_XS_ENABLED_AUDIT_POLICIES
/

drop synonym DBA_XS_PRIVILEGE_GRANTS
/

drop synonym CDB_XS_PRIVILEGE_GRANTS
/

drop synonym ALL_XS_APPLICABLE_OBJECTS
/

drop synonym REDACTION_POLICIES
/

drop synonym REDACTION_COLUMNS
/

drop synonym REDACTION_COLUMNS_DBMS_ERRLOG
/

drop synonym REDACTION_VALUES_FOR_TYPE_FULL
/

drop synonym REDACTION_EXPRESSIONS
/

drop synonym CDB_PRIV_CAPTURES
/

drop synonym CDB_USED_PRIVS
/

drop synonym CDB_USED_SYSPRIVS_PATH
/

drop synonym CDB_USED_OBJPRIVS_PATH
/

drop synonym CDB_USED_USERPRIVS_PATH
/

drop synonym CDB_CHECKED_ROLES_PATH
/

drop synonym CDB_USED_SYSPRIVS
/

drop synonym CDB_USED_OBJPRIVS
/

drop synonym CDB_USED_USERPRIVS
/

drop synonym CDB_CHECKED_ROLES
/

drop synonym CDB_USED_PUBPRIVS
/

drop synonym CDB_UNUSED_PRIVS
/

drop synonym CDB_UNUSED_SYSPRIVS_PATH
/

drop synonym CDB_UNUSED_SYSPRIVS
/

drop synonym CDB_UNUSED_OBJPRIVS_PATH
/

drop synonym CDB_UNUSED_OBJPRIVS
/

drop synonym CDB_UNUSED_USERPRIVS_PATH
/

drop synonym CDB_UNUSED_USERPRIVS
/

drop synonym CDB_UNUSED_GRANTS
/

drop synonym DBA_PRIV_CAPTURES
/

drop synonym DBA_USED_PRIVS
/

drop synonym DBA_USED_SYSPRIVS_PATH
/

drop synonym DBA_USED_OBJPRIVS_PATH
/

drop synonym DBA_USED_USERPRIVS_PATH
/

drop synonym DBA_CHECKED_ROLES_PATH
/

drop synonym DBA_USED_SYSPRIVS
/

drop synonym DBA_USED_OBJPRIVS
/

drop synonym DBA_USED_USERPRIVS
/

drop synonym DBA_USED_PUBPRIVS
/

drop synonym DBA_UNUSED_PRIVS
/

drop synonym DBA_CHECKED_ROLES
/

drop synonym DBA_UNUSED_SYSPRIVS_PATH
/

drop synonym DBA_UNUSED_OBJPRIVS_PATH
/

drop synonym DBA_UNUSED_USERPRIVS_PATH
/

drop synonym DBA_UNUSED_SYSPRIVS
/

drop synonym DBA_UNUSED_OBJPRIVS
/

drop synonym DBA_UNUSED_USERPRIVS
/

drop synonym DBA_UNUSED_GRANTS
/

drop synonym DBA_REDO_DB
/

drop synonym CDB_REDO_DB
/

drop synonym DBA_REDO_LOG
/

drop synonym CDB_REDO_LOG
/

drop synonym DBA_JSON_COLSTORAGE_STATS
/

drop synonym DBA_JSON_COLUMNS
/

drop synonym CDB_JSON_COLUMNS
/

drop synonym USER_JSON_COLUMNS
/

drop synonym ALL_JSON_COLUMNS
/

drop synonym DBA_APPLICATIONS
/

drop synonym DBA_APP_PATCHES
/

drop synonym DBA_APP_VERSIONS
/

drop synonym DBA_APP_STATEMENTS
/

drop synonym DBA_APP_ERRORS
/

drop synonym DBA_APP_PDB_STATUS
/

drop synonym DBA_HANG_MANAGER_PARAMETERS
/

drop synonym CDB_HANG_MANAGER_PARAMETERS
/

drop synonym DBA_EXTERNAL_SCN_ACTIVITY
/

drop synonym DBA_DB_LINK_SOURCES
/

drop synonym CDB_DB_LINK_SOURCES
/

drop synonym CDB_EXTERNAL_SCN_ACTIVITY
/

drop synonym USER_JOINGROUPS
/

drop synonym DBA_JOINGROUPS
/

drop synonym CDB_JOINGROUPS
/

drop synonym USER_IM_EXPRESSIONS
/

drop synonym DBA_IM_EXPRESSIONS
/

drop synonym KU$_PARSED_ITEM
/

drop synonym KU$_PARSED_ITEMS
/

drop synonym KU$_DDL
/

drop synonym KU$_DDLS
/

drop synonym KU$_MULTI_DDL
/

drop synonym KU$_MULTI_DDLS
/

drop synonym KU$_ERRORLINE
/

drop synonym KU$_ERRORLINES
/

drop synonym KU$_SUBMITRESULT
/

drop synonym KU$_SUBMITRESULTS
/

drop synonym KU$_VCNT
/

drop synonym KU$_OBJNUMSET
/

drop synonym KU$_OBJNUMNAM
/

drop synonym KU$_OBJNUMNAMSET
/

drop synonym KU$_OBJNUMPAIR
/

drop synonym KU$_OBJNUMPAIRLIST
/

drop synonym KU$_PROCOBJ_LOC
/

drop synonym KU$_PROCOBJ_LOCS
/

drop synonym KU$_PROCOBJ_LINE
/

drop synonym KU$_PROCOBJ_LINES
/

drop synonym KU$_PROCOBJ_LINES_TAB
/

drop synonym KU$_CHUNK_T
/

drop synonym KU$_CHUNK_LIST_T
/

drop synonym KU$_JAVA_T
/

drop synonym KU$_TACTION_T
/

drop synonym KU$_TACTION_LIST_T
/

drop synonym KU$_AUDOBJ_T
/

drop synonym KU$_AUDIT_LIST_T
/

drop synonym KU$_AUDDEF_T
/

drop synonym KU$_AUDIT_DEFAULT_LIST_T
/

drop synonym KU$_XMLCOLSET_T
/

drop synonym KU$_UNPACKED_ANYDATA_T
/

drop synonym KU$_SOURCE_T
/

drop synonym KU$_SOURCE_LIST_T
/

drop synonym AWRBL_DETAILS_TYPE
/

drop synonym AWRBL_DETAILS_TYPE_TABLE
/

drop synonym AWRBL_METRIC_TYPE
/

drop synonym AWRBL_METRIC_TYPE_TABLE
/

drop synonym AWRRPT_INSTANCE_LIST_TYPE
/

drop synonym AWRRPT_NUMBER_LIST_TYPE
/

drop synonym AWRRPT_VARCHAR256_LIST_TYPE
/

drop synonym AWRRPT_TEXT_TYPE
/

drop synonym AWRRPT_HTML_TYPE
/

drop synonym AWRRPT_TEXT_TYPE_TABLE
/

drop synonym AWRRPT_HTML_TYPE_TABLE
/

drop synonym AWRDRPT_TEXT_TYPE
/

drop synonym AWRDRPT_TEXT_TYPE_TABLE
/

drop synonym AWRSQRPT_TEXT_TYPE
/

drop synonym AWRSQRPT_TEXT_TYPE_TABLE
/

drop synonym AWRRPT_NUM_ARY
/

drop synonym AWRRPT_VCH_ARY
/

drop synonym AWRRPT_CLB_ARY
/

drop synonym AWRRPT_ROW_TYPE
/

drop synonym AWR_OBJECT_INFO_TYPE
/

drop synonym AWR_OBJECT_INFO_TABLE_TYPE
/

drop synonym AWR_EXPORT_DUMP_ID_TYPE
/

drop synonym WRW_MAILPKG_INFO_TYPE
/

drop synonym AWR_ROOT_DATABASE_INSTANCE
/

drop synonym AWR_ROOT_SNAPSHOT
/

drop synonym AWR_ROOT_SNAP_ERROR
/

drop synonym AWR_ROOT_COLORED_SQL
/

drop synonym AWR_ROOT_BASELINE_METADATA
/

drop synonym AWR_ROOT_BASELINE_TEMPLATE
/

drop synonym AWR_ROOT_WR_CONTROL
/

drop synonym AWR_ROOT_TABLESPACE
/

drop synonym AWR_ROOT_DATAFILE
/

drop synonym AWR_ROOT_FILESTATXS
/

drop synonym AWR_ROOT_TEMPFILE
/

drop synonym AWR_ROOT_TEMPSTATXS
/

drop synonym AWR_ROOT_COMP_IOSTAT
/

drop synonym AWR_ROOT_SQLSTAT
/

drop synonym AWR_ROOT_SQLTEXT
/

drop synonym AWR_ROOT_SQL_SUMMARY
/

drop synonym AWR_ROOT_SQL_PLAN
/

drop synonym AWR_ROOT_SQL_BIND_METADATA
/

drop synonym AWR_ROOT_OPTIMIZER_ENV
/

drop synonym AWR_ROOT_EVENT_NAME
/

drop synonym AWR_ROOT_SYSTEM_EVENT
/

drop synonym AWR_ROOT_CON_SYSTEM_EVENT
/

drop synonym AWR_ROOT_BG_EVENT_SUMMARY
/

drop synonym AWR_ROOT_CHANNEL_WAITS
/

drop synonym AWR_ROOT_WAITSTAT
/

drop synonym AWR_ROOT_ENQUEUE_STAT
/

drop synonym AWR_ROOT_LATCH_NAME
/

drop synonym AWR_ROOT_LATCH
/

drop synonym AWR_ROOT_LATCH_CHILDREN
/

drop synonym AWR_ROOT_LATCH_PARENT
/

drop synonym AWR_ROOT_LATCH_MISSES_SUMMARY
/

drop synonym AWR_ROOT_EVENT_HISTOGRAM
/

drop synonym AWR_ROOT_MUTEX_SLEEP
/

drop synonym AWR_ROOT_LIBRARYCACHE
/

drop synonym AWR_ROOT_DB_CACHE_ADVICE
/

drop synonym AWR_ROOT_BUFFER_POOL_STAT
/

drop synonym AWR_ROOT_ROWCACHE_SUMMARY
/

drop synonym AWR_ROOT_SGA
/

drop synonym AWR_ROOT_SGASTAT
/

drop synonym AWR_ROOT_PGASTAT
/

drop synonym AWR_ROOT_PROCESS_MEM_SUMMARY
/

drop synonym AWR_ROOT_RESOURCE_LIMIT
/

drop synonym AWR_ROOT_SHARED_POOL_ADVICE
/

drop synonym AWR_ROOT_STREAMS_POOL_ADVICE
/

drop synonym AWR_ROOT_SQL_WORKAREA_HSTGRM
/

drop synonym AWR_ROOT_PGA_TARGET_ADVICE
/

drop synonym AWR_ROOT_SGA_TARGET_ADVICE
/

drop synonym AWR_ROOT_MEMORY_TARGET_ADVICE
/

drop synonym AWR_ROOT_MEMORY_RESIZE_OPS
/

drop synonym AWR_ROOT_INSTANCE_RECOVERY
/

drop synonym AWR_ROOT_RECOVERY_PROGRESS
/

drop synonym AWR_ROOT_JAVA_POOL_ADVICE
/

drop synonym AWR_ROOT_THREAD
/

drop synonym AWR_ROOT_STAT_NAME
/

drop synonym AWR_ROOT_SYSSTAT_ID
/

drop synonym AWR_ROOT_SYSSTAT
/

drop synonym AWR_ROOT_CON_SYSSTAT
/

drop synonym AWR_ROOT_SYS_TIME_MODEL
/

drop synonym AWR_ROOT_CON_SYS_TIME_MODEL
/

drop synonym AWR_ROOT_OSSTAT_NAME
/

drop synonym AWR_ROOT_OSSTAT
/

drop synonym AWR_ROOT_PARAMETER_NAME
/

drop synonym AWR_ROOT_PARAMETER
/

drop synonym AWR_ROOT_MVPARAMETER
/

drop synonym AWR_ROOT_UNDOSTAT
/

drop synonym AWR_ROOT_SEG_STAT
/

drop synonym AWR_ROOT_SEG_STAT_OBJ
/

drop synonym AWR_ROOT_METRIC_NAME
/

drop synonym AWR_ROOT_SYSMETRIC_HISTORY
/

drop synonym AWR_ROOT_SYSMETRIC_SUMMARY
/

drop synonym AWR_ROOT_CON_SYSMETRIC_HIST
/

drop synonym AWR_ROOT_CON_SYSMETRIC_SUMM
/

drop synonym AWR_ROOT_SESSMETRIC_HISTORY
/

drop synonym AWR_ROOT_FILEMETRIC_HISTORY
/

drop synonym AWR_ROOT_WAITCLASSMET_HISTORY
/

drop synonym AWR_ROOT_DLM_MISC
/

drop synonym AWR_ROOT_CR_BLOCK_SERVER
/

drop synonym AWR_ROOT_CURRENT_BLOCK_SERVER
/

drop synonym AWR_ROOT_INST_CACHE_TRANSFER
/

drop synonym AWR_ROOT_PLAN_OPERATION_NAME
/

drop synonym AWR_ROOT_PLAN_OPTION_NAME
/

drop synonym AWR_ROOT_SQLCOMMAND_NAME
/

drop synonym AWR_ROOT_TOPLEVELCALL_NAME
/

drop synonym AWR_ROOT_ACTIVE_SESS_HISTORY
/

drop synonym AWR_ROOT_ASH_SNAPSHOT
/

drop synonym AWR_ROOT_TABLESPACE_STAT
/

drop synonym AWR_ROOT_LOG
/

drop synonym AWR_ROOT_MTTR_TARGET_ADVICE
/

drop synonym AWR_ROOT_TBSPC_SPACE_USAGE
/

drop synonym AWR_ROOT_SERVICE_NAME
/

drop synonym AWR_ROOT_SERVICE_STAT
/

drop synonym AWR_ROOT_SERVICE_WAIT_CLASS
/

drop synonym AWR_ROOT_SESS_TIME_STATS
/

drop synonym AWR_ROOT_STREAMS_CAPTURE
/

drop synonym AWR_ROOT_CAPTURE
/

drop synonym AWR_ROOT_STREAMS_APPLY_SUM
/

drop synonym AWR_ROOT_APPLY_SUMMARY
/

drop synonym AWR_ROOT_BUFFERED_QUEUES
/

drop synonym AWR_ROOT_BUFFERED_SUBSCRIBERS
/

drop synonym AWR_ROOT_RULE_SET
/

drop synonym AWR_ROOT_PERSISTENT_QUEUES
/

drop synonym AWR_ROOT_PERSISTENT_SUBS
/

drop synonym AWR_ROOT_SESS_SGA_STATS
/

drop synonym AWR_ROOT_REPLICATION_TBL_STATS
/

drop synonym AWR_ROOT_REPLICATION_TXN_STATS
/

drop synonym AWR_ROOT_IOSTAT_FUNCTION
/

drop synonym AWR_ROOT_IOSTAT_FUNCTION_NAME
/

drop synonym AWR_ROOT_IOSTAT_FILETYPE
/

drop synonym AWR_ROOT_IOSTAT_FILETYPE_NAME
/

drop synonym AWR_ROOT_IOSTAT_DETAIL
/

drop synonym AWR_ROOT_RSRC_CONSUMER_GROUP
/

drop synonym AWR_ROOT_RSRC_PLAN
/

drop synonym AWR_ROOT_RSRC_METRIC
/

drop synonym AWR_ROOT_RSRC_PDB_METRIC
/

drop synonym AWR_ROOT_CLUSTER_INTERCON
/

drop synonym AWR_ROOT_MEM_DYNAMIC_COMP
/

drop synonym AWR_ROOT_IC_CLIENT_STATS
/

drop synonym AWR_ROOT_IC_DEVICE_STATS
/

drop synonym AWR_ROOT_INTERCONNECT_PINGS
/

drop synonym AWR_ROOT_DISPATCHER
/

drop synonym AWR_ROOT_SHARED_SERVER_SUMMARY
/

drop synonym AWR_ROOT_DYN_REMASTER_STATS
/

drop synonym AWR_ROOT_LMS_STATS
/

drop synonym AWR_ROOT_PERSISTENT_QMN_CACHE
/

drop synonym AWR_ROOT_PDB_INSTANCE
/

drop synonym AWR_ROOT_PDB_IN_SNAP
/

drop synonym AWR_ROOT_CELL_CONFIG
/

drop synonym AWR_ROOT_CELL_CONFIG_DETAIL
/

drop synonym AWR_ROOT_ASM_DISKGROUP
/

drop synonym AWR_ROOT_ASM_DISKGROUP_STAT
/

drop synonym AWR_ROOT_ASM_BAD_DISK
/

drop synonym AWR_ROOT_CELL_NAME
/

drop synonym AWR_ROOT_CELL_DISKTYPE
/

drop synonym AWR_ROOT_CELL_DISK_NAME
/

drop synonym AWR_ROOT_CELL_GLOBAL_SUMMARY
/

drop synonym AWR_ROOT_CELL_DISK_SUMMARY
/

drop synonym AWR_ROOT_CELL_METRIC_DESC
/

drop synonym AWR_ROOT_CELL_IOREASON_NAME
/

drop synonym AWR_ROOT_CELL_GLOBAL
/

drop synonym AWR_ROOT_CELL_IOREASON
/

drop synonym AWR_ROOT_CELL_DB
/

drop synonym AWR_ROOT_CELL_OPEN_ALERTS
/

drop synonym AWR_ROOT_IM_SEG_STAT
/

drop synonym AWR_ROOT_IM_SEG_STAT_OBJ
/

drop synonym AWR_ROOT_WR_SETTINGS
/

drop synonym AWR_ROOT_PROCESS_WAITTIME
/

drop synonym AWR_ROOT_ASM_DISK_STAT_SUMMARY
/

drop synonym AWR_ROOT_TABLE_SETTINGS
/

drop synonym AWR_PDB_DATABASE_INSTANCE
/

drop synonym AWR_PDB_SNAPSHOT
/

drop synonym AWR_PDB_SNAP_ERROR
/

drop synonym AWR_PDB_COLORED_SQL
/

drop synonym AWR_PDB_BASELINE_METADATA
/

drop synonym AWR_PDB_BASELINE_TEMPLATE
/

drop synonym AWR_PDB_WR_CONTROL
/

drop synonym AWR_PDB_TABLESPACE
/

drop synonym AWR_PDB_DATAFILE
/

drop synonym AWR_PDB_FILESTATXS
/

drop synonym AWR_PDB_TEMPFILE
/

drop synonym AWR_PDB_TEMPSTATXS
/

drop synonym AWR_PDB_COMP_IOSTAT
/

drop synonym AWR_PDB_SQLSTAT
/

drop synonym AWR_PDB_SQLTEXT
/

drop synonym AWR_PDB_SQL_SUMMARY
/

drop synonym AWR_PDB_SQL_PLAN
/

drop synonym AWR_PDB_SQL_BIND_METADATA
/

drop synonym AWR_PDB_OPTIMIZER_ENV
/

drop synonym AWR_PDB_EVENT_NAME
/

drop synonym AWR_PDB_SYSTEM_EVENT
/

drop synonym AWR_PDB_CON_SYSTEM_EVENT
/

drop synonym AWR_PDB_BG_EVENT_SUMMARY
/

drop synonym AWR_PDB_CHANNEL_WAITS
/

drop synonym AWR_PDB_WAITSTAT
/

drop synonym AWR_PDB_ENQUEUE_STAT
/

drop synonym AWR_PDB_LATCH_NAME
/

drop synonym AWR_PDB_LATCH
/

drop synonym AWR_PDB_LATCH_CHILDREN
/

drop synonym AWR_PDB_LATCH_PARENT
/

drop synonym AWR_PDB_LATCH_MISSES_SUMMARY
/

drop synonym AWR_PDB_EVENT_HISTOGRAM
/

drop synonym AWR_PDB_MUTEX_SLEEP
/

drop synonym AWR_PDB_LIBRARYCACHE
/

drop synonym AWR_PDB_DB_CACHE_ADVICE
/

drop synonym AWR_PDB_BUFFER_POOL_STAT
/

drop synonym AWR_PDB_ROWCACHE_SUMMARY
/

drop synonym AWR_PDB_SGA
/

drop synonym AWR_PDB_SGASTAT
/

drop synonym AWR_PDB_PGASTAT
/

drop synonym AWR_PDB_PROCESS_MEM_SUMMARY
/

drop synonym AWR_PDB_RESOURCE_LIMIT
/

drop synonym AWR_PDB_SHARED_POOL_ADVICE
/

drop synonym AWR_PDB_STREAMS_POOL_ADVICE
/

drop synonym AWR_PDB_SQL_WORKAREA_HSTGRM
/

drop synonym AWR_PDB_PGA_TARGET_ADVICE
/

drop synonym AWR_PDB_SGA_TARGET_ADVICE
/

drop synonym AWR_PDB_MEMORY_TARGET_ADVICE
/

drop synonym AWR_PDB_MEMORY_RESIZE_OPS
/

drop synonym AWR_PDB_INSTANCE_RECOVERY
/

drop synonym AWR_PDB_RECOVERY_PROGRESS
/

drop synonym AWR_PDB_JAVA_POOL_ADVICE
/

drop synonym AWR_PDB_THREAD
/

drop synonym AWR_PDB_STAT_NAME
/

drop synonym AWR_PDB_SYSSTAT
/

drop synonym AWR_PDB_CON_SYSSTAT
/

drop synonym AWR_PDB_SYS_TIME_MODEL
/

drop synonym AWR_PDB_CON_SYS_TIME_MODEL
/

drop synonym AWR_PDB_OSSTAT_NAME
/

drop synonym AWR_PDB_OSSTAT
/

drop synonym AWR_PDB_PARAMETER_NAME
/

drop synonym AWR_PDB_PARAMETER
/

drop synonym AWR_PDB_MVPARAMETER
/

drop synonym AWR_PDB_UNDOSTAT
/

drop synonym AWR_PDB_SEG_STAT
/

drop synonym AWR_PDB_SEG_STAT_OBJ
/

drop synonym AWR_PDB_METRIC_NAME
/

drop synonym AWR_PDB_SYSMETRIC_HISTORY
/

drop synonym AWR_PDB_SYSMETRIC_SUMMARY
/

drop synonym AWR_PDB_CON_SYSMETRIC_HIST
/

drop synonym AWR_PDB_CON_SYSMETRIC_SUMM
/

drop synonym AWR_PDB_SESSMETRIC_HISTORY
/

drop synonym AWR_PDB_FILEMETRIC_HISTORY
/

drop synonym AWR_PDB_WAITCLASSMET_HISTORY
/

drop synonym AWR_PDB_DLM_MISC
/

drop synonym AWR_PDB_CR_BLOCK_SERVER
/

drop synonym AWR_PDB_CURRENT_BLOCK_SERVER
/

drop synonym AWR_PDB_INST_CACHE_TRANSFER
/

drop synonym AWR_PDB_PLAN_OPERATION_NAME
/

drop synonym AWR_PDB_PLAN_OPTION_NAME
/

drop synonym AWR_PDB_SQLCOMMAND_NAME
/

drop synonym AWR_PDB_TOPLEVELCALL_NAME
/

drop synonym AWR_PDB_ACTIVE_SESS_HISTORY
/

drop synonym AWR_PDB_ASH_SNAPSHOT
/

drop synonym AWR_PDB_TABLESPACE_STAT
/

drop synonym AWR_PDB_LOG
/

drop synonym AWR_PDB_MTTR_TARGET_ADVICE
/

drop synonym AWR_PDB_TBSPC_SPACE_USAGE
/

drop synonym AWR_PDB_SERVICE_NAME
/

drop synonym AWR_PDB_SERVICE_STAT
/

drop synonym AWR_PDB_SERVICE_WAIT_CLASS
/

drop synonym AWR_PDB_SESS_TIME_STATS
/

drop synonym AWR_PDB_STREAMS_CAPTURE
/

drop synonym AWR_PDB_CAPTURE
/

drop synonym AWR_PDB_STREAMS_APPLY_SUM
/

drop synonym AWR_PDB_APPLY_SUMMARY
/

drop synonym AWR_PDB_BUFFERED_QUEUES
/

drop synonym AWR_PDB_BUFFERED_SUBSCRIBERS
/

drop synonym AWR_PDB_RULE_SET
/

drop synonym AWR_PDB_PERSISTENT_QUEUES
/

drop synonym AWR_PDB_PERSISTENT_SUBS
/

drop synonym AWR_PDB_SESS_SGA_STATS
/

drop synonym AWR_PDB_REPLICATION_TBL_STATS
/

drop synonym AWR_PDB_REPLICATION_TXN_STATS
/

drop synonym AWR_PDB_IOSTAT_FUNCTION
/

drop synonym AWR_PDB_IOSTAT_FUNCTION_NAME
/

drop synonym AWR_PDB_IOSTAT_FILETYPE
/

drop synonym AWR_PDB_IOSTAT_FILETYPE_NAME
/

drop synonym AWR_PDB_IOSTAT_DETAIL
/

drop synonym AWR_PDB_RSRC_CONSUMER_GROUP
/

drop synonym AWR_PDB_RSRC_PLAN
/

drop synonym AWR_PDB_RSRC_METRIC
/

drop synonym AWR_PDB_RSRC_PDB_METRIC
/

drop synonym AWR_PDB_CLUSTER_INTERCON
/

drop synonym AWR_PDB_MEM_DYNAMIC_COMP
/

drop synonym AWR_PDB_IC_CLIENT_STATS
/

drop synonym AWR_PDB_IC_DEVICE_STATS
/

drop synonym AWR_PDB_INTERCONNECT_PINGS
/

drop synonym AWR_PDB_DISPATCHER
/

drop synonym AWR_PDB_SHARED_SERVER_SUMMARY
/

drop synonym AWR_PDB_DYN_REMASTER_STATS
/

drop synonym AWR_PDB_LMS_STATS
/

drop synonym AWR_PDB_PERSISTENT_QMN_CACHE
/

drop synonym AWR_PDB_PDB_INSTANCE
/

drop synonym AWR_PDB_PDB_IN_SNAP
/

drop synonym AWR_PDB_CELL_CONFIG
/

drop synonym AWR_PDB_CELL_CONFIG_DETAIL
/

drop synonym AWR_PDB_ASM_DISKGROUP
/

drop synonym AWR_PDB_ASM_DISKGROUP_STAT
/

drop synonym AWR_PDB_ASM_BAD_DISK
/

drop synonym AWR_PDB_CELL_NAME
/

drop synonym AWR_PDB_CELL_DISKTYPE
/

drop synonym AWR_PDB_CELL_DISK_NAME
/

drop synonym AWR_PDB_CELL_GLOBAL_SUMMARY
/

drop synonym AWR_PDB_CELL_DISK_SUMMARY
/

drop synonym AWR_PDB_CELL_METRIC_DESC
/

drop synonym AWR_PDB_CELL_IOREASON_NAME
/

drop synonym AWR_PDB_CELL_GLOBAL
/

drop synonym AWR_PDB_CELL_IOREASON
/

drop synonym AWR_PDB_CELL_DB
/

drop synonym AWR_PDB_CELL_OPEN_ALERTS
/

drop synonym AWR_PDB_IM_SEG_STAT
/

drop synonym AWR_PDB_IM_SEG_STAT_OBJ
/

drop synonym AWR_PDB_WR_SETTINGS
/

drop synonym AWR_PDB_PROCESS_WAITTIME
/

drop synonym AWR_PDB_ASM_DISK_STAT_SUMMARY
/

drop synonym AWR_PDB_TABLE_SETTINGS
/

drop synonym AWR_CDB_DATABASE_INSTANCE
/

drop synonym AWR_CDB_SNAPSHOT
/

drop synonym AWR_CDB_SNAP_ERROR
/

drop synonym AWR_CDB_COLORED_SQL
/

drop synonym AWR_CDB_BASELINE_METADATA
/

drop synonym AWR_CDB_BASELINE_TEMPLATE
/

drop synonym AWR_CDB_WR_CONTROL
/

drop synonym AWR_CDB_TABLESPACE
/

drop synonym AWR_CDB_DATAFILE
/

drop synonym AWR_CDB_FILESTATXS
/

drop synonym AWR_CDB_TEMPFILE
/

drop synonym AWR_CDB_TEMPSTATXS
/

drop synonym AWR_CDB_COMP_IOSTAT
/

drop synonym AWR_CDB_SQLSTAT
/

drop synonym AWR_CDB_SQLTEXT
/

drop synonym AWR_CDB_SQL_SUMMARY
/

drop synonym AWR_CDB_SQL_PLAN
/

drop synonym AWR_CDB_SQL_BIND_METADATA
/

drop synonym AWR_CDB_OPTIMIZER_ENV
/

drop synonym AWR_CDB_EVENT_NAME
/

drop synonym AWR_CDB_SYSTEM_EVENT
/

drop synonym AWR_CDB_CON_SYSTEM_EVENT
/

drop synonym AWR_CDB_BG_EVENT_SUMMARY
/

drop synonym AWR_CDB_CHANNEL_WAITS
/

drop synonym AWR_CDB_WAITSTAT
/

drop synonym AWR_CDB_ENQUEUE_STAT
/

drop synonym AWR_CDB_LATCH_NAME
/

drop synonym AWR_CDB_LATCH
/

drop synonym AWR_CDB_LATCH_CHILDREN
/

drop synonym AWR_CDB_LATCH_PARENT
/

drop synonym AWR_CDB_LATCH_MISSES_SUMMARY
/

drop synonym AWR_CDB_EVENT_HISTOGRAM
/

drop synonym AWR_CDB_MUTEX_SLEEP
/

drop synonym AWR_CDB_LIBRARYCACHE
/

drop synonym AWR_CDB_DB_CACHE_ADVICE
/

drop synonym AWR_CDB_BUFFER_POOL_STAT
/

drop synonym AWR_CDB_ROWCACHE_SUMMARY
/

drop synonym AWR_CDB_SGA
/

drop synonym AWR_CDB_SGASTAT
/

drop synonym AWR_CDB_PGASTAT
/

drop synonym AWR_CDB_PROCESS_MEM_SUMMARY
/

drop synonym AWR_CDB_RESOURCE_LIMIT
/

drop synonym AWR_CDB_SHARED_POOL_ADVICE
/

drop synonym AWR_CDB_STREAMS_POOL_ADVICE
/

drop synonym AWR_CDB_SQL_WORKAREA_HSTGRM
/

drop synonym AWR_CDB_PGA_TARGET_ADVICE
/

drop synonym AWR_CDB_SGA_TARGET_ADVICE
/

drop synonym AWR_CDB_MEMORY_TARGET_ADVICE
/

drop synonym AWR_CDB_MEMORY_RESIZE_OPS
/

drop synonym AWR_CDB_INSTANCE_RECOVERY
/

drop synonym AWR_CDB_RECOVERY_PROGRESS
/

drop synonym AWR_CDB_JAVA_POOL_ADVICE
/

drop synonym AWR_CDB_THREAD
/

drop synonym AWR_CDB_STAT_NAME
/

drop synonym AWR_CDB_SYSSTAT_ID
/

drop synonym AWR_CDB_SYSSTAT
/

drop synonym AWR_CDB_CON_SYSSTAT
/

drop synonym AWR_CDB_SYS_TIME_MODEL
/

drop synonym AWR_CDB_CON_SYS_TIME_MODEL
/

drop synonym AWR_CDB_OSSTAT_NAME
/

drop synonym AWR_CDB_OSSTAT
/

drop synonym AWR_CDB_PARAMETER_NAME
/

drop synonym AWR_CDB_PARAMETER
/

drop synonym AWR_CDB_MVPARAMETER
/

drop synonym AWR_CDB_UNDOSTAT
/

drop synonym AWR_CDB_SEG_STAT
/

drop synonym AWR_CDB_SEG_STAT_OBJ
/

drop synonym AWR_CDB_METRIC_NAME
/

drop synonym AWR_CDB_SYSMETRIC_HISTORY
/

drop synonym AWR_CDB_SYSMETRIC_SUMMARY
/

drop synonym AWR_CDB_CON_SYSMETRIC_HIST
/

drop synonym AWR_CDB_CON_SYSMETRIC_SUMM
/

drop synonym AWR_CDB_SESSMETRIC_HISTORY
/

drop synonym AWR_CDB_FILEMETRIC_HISTORY
/

drop synonym AWR_CDB_WAITCLASSMET_HISTORY
/

drop synonym AWR_CDB_DLM_MISC
/

drop synonym AWR_CDB_CR_BLOCK_SERVER
/

drop synonym AWR_CDB_CURRENT_BLOCK_SERVER
/

drop synonym AWR_CDB_INST_CACHE_TRANSFER
/

drop synonym AWR_CDB_PLAN_OPERATION_NAME
/

drop synonym AWR_CDB_PLAN_OPTION_NAME
/

drop synonym AWR_CDB_SQLCOMMAND_NAME
/

drop synonym AWR_CDB_TOPLEVELCALL_NAME
/

drop synonym AWR_CDB_ACTIVE_SESS_HISTORY
/

drop synonym AWR_CDB_ASH_SNAPSHOT
/

drop synonym AWR_CDB_TABLESPACE_STAT
/

drop synonym AWR_CDB_LOG
/

drop synonym AWR_CDB_MTTR_TARGET_ADVICE
/

drop synonym AWR_CDB_TBSPC_SPACE_USAGE
/

drop synonym AWR_CDB_SERVICE_NAME
/

drop synonym AWR_CDB_SERVICE_STAT
/

drop synonym AWR_CDB_SERVICE_WAIT_CLASS
/

drop synonym AWR_CDB_SESS_TIME_STATS
/

drop synonym AWR_CDB_STREAMS_CAPTURE
/

drop synonym AWR_CDB_CAPTURE
/

drop synonym AWR_CDB_STREAMS_APPLY_SUM
/

drop synonym AWR_CDB_APPLY_SUMMARY
/

drop synonym AWR_CDB_BUFFERED_QUEUES
/

drop synonym AWR_CDB_BUFFERED_SUBSCRIBERS
/

drop synonym AWR_CDB_RULE_SET
/

drop synonym AWR_CDB_PERSISTENT_QUEUES
/

drop synonym AWR_CDB_PERSISTENT_SUBS
/

drop synonym AWR_CDB_SESS_SGA_STATS
/

drop synonym AWR_CDB_REPLICATION_TBL_STATS
/

drop synonym AWR_CDB_REPLICATION_TXN_STATS
/

drop synonym AWR_CDB_IOSTAT_FUNCTION
/

drop synonym AWR_CDB_IOSTAT_FUNCTION_NAME
/

drop synonym AWR_CDB_IOSTAT_FILETYPE
/

drop synonym AWR_CDB_IOSTAT_FILETYPE_NAME
/

drop synonym AWR_CDB_IOSTAT_DETAIL
/

drop synonym AWR_CDB_RSRC_CONSUMER_GROUP
/

drop synonym AWR_CDB_RSRC_PLAN
/

drop synonym AWR_CDB_RSRC_METRIC
/

drop synonym AWR_CDB_RSRC_PDB_METRIC
/

drop synonym AWR_CDB_CLUSTER_INTERCON
/

drop synonym AWR_CDB_MEM_DYNAMIC_COMP
/

drop synonym AWR_CDB_IC_CLIENT_STATS
/

drop synonym AWR_CDB_IC_DEVICE_STATS
/

drop synonym AWR_CDB_INTERCONNECT_PINGS
/

drop synonym AWR_CDB_DISPATCHER
/

drop synonym AWR_CDB_SHARED_SERVER_SUMMARY
/

drop synonym AWR_CDB_DYN_REMASTER_STATS
/

drop synonym AWR_CDB_LMS_STATS
/

drop synonym AWR_CDB_PERSISTENT_QMN_CACHE
/

drop synonym AWR_CDB_PDB_INSTANCE
/

drop synonym AWR_CDB_PDB_IN_SNAP
/

drop synonym AWR_CDB_CELL_CONFIG
/

drop synonym AWR_CDB_CELL_CONFIG_DETAIL
/

drop synonym AWR_CDB_ASM_DISKGROUP
/

drop synonym AWR_CDB_ASM_DISKGROUP_STAT
/

drop synonym AWR_CDB_ASM_BAD_DISK
/

drop synonym AWR_CDB_CELL_NAME
/

drop synonym AWR_CDB_CELL_DISKTYPE
/

drop synonym AWR_CDB_CELL_DISK_NAME
/

drop synonym AWR_CDB_CELL_GLOBAL_SUMMARY
/

drop synonym AWR_CDB_CELL_DISK_SUMMARY
/

drop synonym AWR_CDB_CELL_METRIC_DESC
/

drop synonym AWR_CDB_CELL_IOREASON_NAME
/

drop synonym AWR_CDB_CELL_GLOBAL
/

drop synonym AWR_CDB_CELL_IOREASON
/

drop synonym AWR_CDB_CELL_DB
/

drop synonym AWR_CDB_CELL_OPEN_ALERTS
/

drop synonym AWR_CDB_IM_SEG_STAT
/

drop synonym AWR_CDB_IM_SEG_STAT_OBJ
/

drop synonym AWR_CDB_WR_SETTINGS
/

drop synonym AWR_CDB_PROCESS_WAITTIME
/

drop synonym AWR_CDB_ASM_DISK_STAT_SUMMARY
/

drop synonym AWR_CDB_TABLE_SETTINGS
/

drop synonym DBA_HIST_DATABASE_INSTANCE
/

drop synonym CDB_HIST_DATABASE_INSTANCE
/

drop synonym DBA_HIST_SNAPSHOT
/

drop synonym CDB_HIST_SNAPSHOT
/

drop synonym DBA_HIST_SNAP_ERROR
/

drop synonym CDB_HIST_SNAP_ERROR
/

drop synonym DBA_HIST_COLORED_SQL
/

drop synonym CDB_HIST_COLORED_SQL
/

drop synonym DBA_HIST_BASELINE_METADATA
/

drop synonym CDB_HIST_BASELINE_METADATA
/

drop synonym DBA_HIST_BASELINE_TEMPLATE
/

drop synonym CDB_HIST_BASELINE_TEMPLATE
/

drop synonym DBA_HIST_WR_CONTROL
/

drop synonym CDB_HIST_WR_CONTROL
/

drop synonym DBA_HIST_TABLESPACE
/

drop synonym CDB_HIST_TABLESPACE
/

drop synonym DBA_HIST_DATAFILE
/

drop synonym CDB_HIST_DATAFILE
/

drop synonym DBA_HIST_FILESTATXS
/

drop synonym CDB_HIST_FILESTATXS
/

drop synonym DBA_HIST_TEMPFILE
/

drop synonym CDB_HIST_TEMPFILE
/

drop synonym DBA_HIST_TEMPSTATXS
/

drop synonym CDB_HIST_TEMPSTATXS
/

drop synonym DBA_HIST_COMP_IOSTAT
/

drop synonym CDB_HIST_COMP_IOSTAT
/

drop synonym DBA_HIST_SQLSTAT
/

drop synonym CDB_HIST_SQLSTAT
/

drop synonym DBA_HIST_SQLTEXT
/

drop synonym CDB_HIST_SQLTEXT
/

drop synonym DBA_HIST_SQL_SUMMARY
/

drop synonym CDB_HIST_SQL_SUMMARY
/

drop synonym DBA_HIST_SQL_PLAN
/

drop synonym CDB_HIST_SQL_PLAN
/

drop synonym DBA_HIST_SQL_BIND_METADATA
/

drop synonym CDB_HIST_SQL_BIND_METADATA
/

drop synonym DBA_HIST_OPTIMIZER_ENV
/

drop synonym CDB_HIST_OPTIMIZER_ENV
/

drop synonym DBA_HIST_EVENT_NAME
/

drop synonym CDB_HIST_EVENT_NAME
/

drop synonym DBA_HIST_SYSTEM_EVENT
/

drop synonym CDB_HIST_SYSTEM_EVENT
/

drop synonym DBA_HIST_CON_SYSTEM_EVENT
/

drop synonym CDB_HIST_CON_SYSTEM_EVENT
/

drop synonym DBA_HIST_BG_EVENT_SUMMARY
/

drop synonym CDB_HIST_BG_EVENT_SUMMARY
/

drop synonym DBA_HIST_CHANNEL_WAITS
/

drop synonym CDB_HIST_CHANNEL_WAITS
/

drop synonym DBA_HIST_WAITSTAT
/

drop synonym CDB_HIST_WAITSTAT
/

drop synonym DBA_HIST_ENQUEUE_STAT
/

drop synonym CDB_HIST_ENQUEUE_STAT
/

drop synonym DBA_HIST_LATCH_NAME
/

drop synonym CDB_HIST_LATCH_NAME
/

drop synonym DBA_HIST_LATCH
/

drop synonym CDB_HIST_LATCH
/

drop synonym DBA_HIST_LATCH_CHILDREN
/

drop synonym CDB_HIST_LATCH_CHILDREN
/

drop synonym DBA_HIST_LATCH_PARENT
/

drop synonym CDB_HIST_LATCH_PARENT
/

drop synonym DBA_HIST_LATCH_MISSES_SUMMARY
/

drop synonym CDB_HIST_LATCH_MISSES_SUMMARY
/

drop synonym DBA_HIST_EVENT_HISTOGRAM
/

drop synonym CDB_HIST_EVENT_HISTOGRAM
/

drop synonym DBA_HIST_MUTEX_SLEEP
/

drop synonym CDB_HIST_MUTEX_SLEEP
/

drop synonym DBA_HIST_LIBRARYCACHE
/

drop synonym CDB_HIST_LIBRARYCACHE
/

drop synonym DBA_HIST_DB_CACHE_ADVICE
/

drop synonym CDB_HIST_DB_CACHE_ADVICE
/

drop synonym DBA_HIST_BUFFER_POOL_STAT
/

drop synonym CDB_HIST_BUFFER_POOL_STAT
/

drop synonym DBA_HIST_ROWCACHE_SUMMARY
/

drop synonym CDB_HIST_ROWCACHE_SUMMARY
/

drop synonym DBA_HIST_SGA
/

drop synonym CDB_HIST_SGA
/

drop synonym DBA_HIST_SGASTAT
/

drop synonym CDB_HIST_SGASTAT
/

drop synonym DBA_HIST_PGASTAT
/

drop synonym CDB_HIST_PGASTAT
/

drop synonym DBA_HIST_PROCESS_MEM_SUMMARY
/

drop synonym CDB_HIST_PROCESS_MEM_SUMMARY
/

drop synonym DBA_HIST_RESOURCE_LIMIT
/

drop synonym CDB_HIST_RESOURCE_LIMIT
/

drop synonym DBA_HIST_SHARED_POOL_ADVICE
/

drop synonym CDB_HIST_SHARED_POOL_ADVICE
/

drop synonym DBA_HIST_STREAMS_POOL_ADVICE
/

drop synonym CDB_HIST_STREAMS_POOL_ADVICE
/

drop synonym DBA_HIST_SQL_WORKAREA_HSTGRM
/

drop synonym CDB_HIST_SQL_WORKAREA_HSTGRM
/

drop synonym DBA_HIST_PGA_TARGET_ADVICE
/

drop synonym CDB_HIST_PGA_TARGET_ADVICE
/

drop synonym DBA_HIST_SGA_TARGET_ADVICE
/

drop synonym CDB_HIST_SGA_TARGET_ADVICE
/

drop synonym DBA_HIST_MEMORY_TARGET_ADVICE
/

drop synonym CDB_HIST_MEMORY_TARGET_ADVICE
/

drop synonym DBA_HIST_MEMORY_RESIZE_OPS
/

drop synonym CDB_HIST_MEMORY_RESIZE_OPS
/

drop synonym DBA_HIST_INSTANCE_RECOVERY
/

drop synonym CDB_HIST_INSTANCE_RECOVERY
/

drop synonym DBA_HIST_RECOVERY_PROGRESS
/

drop synonym CDB_HIST_RECOVERY_PROGRESS
/

drop synonym DBA_HIST_JAVA_POOL_ADVICE
/

drop synonym CDB_HIST_JAVA_POOL_ADVICE
/

drop synonym DBA_HIST_THREAD
/

drop synonym CDB_HIST_THREAD
/

drop synonym DBA_HIST_STAT_NAME
/

drop synonym CDB_HIST_STAT_NAME
/

drop synonym DBA_HIST_SYSSTAT
/

drop synonym CDB_HIST_SYSSTAT
/

drop synonym DBA_HIST_CON_SYSSTAT
/

drop synonym CDB_HIST_CON_SYSSTAT
/

drop synonym DBA_HIST_SYS_TIME_MODEL
/

drop synonym CDB_HIST_SYS_TIME_MODEL
/

drop synonym DBA_HIST_CON_SYS_TIME_MODEL
/

drop synonym CDB_HIST_CON_SYS_TIME_MODEL
/

drop synonym DBA_HIST_OSSTAT_NAME
/

drop synonym CDB_HIST_OSSTAT_NAME
/

drop synonym DBA_HIST_OSSTAT
/

drop synonym CDB_HIST_OSSTAT
/

drop synonym DBA_HIST_PARAMETER_NAME
/

drop synonym CDB_HIST_PARAMETER_NAME
/

drop synonym DBA_HIST_PARAMETER
/

drop synonym CDB_HIST_PARAMETER
/

drop synonym DBA_HIST_MVPARAMETER
/

drop synonym CDB_HIST_MVPARAMETER
/

drop synonym DBA_HIST_UNDOSTAT
/

drop synonym CDB_HIST_UNDOSTAT
/

drop synonym DBA_HIST_SEG_STAT
/

drop synonym CDB_HIST_SEG_STAT
/

drop synonym DBA_HIST_SEG_STAT_OBJ
/

drop synonym CDB_HIST_SEG_STAT_OBJ
/

drop synonym DBA_HIST_METRIC_NAME
/

drop synonym CDB_HIST_METRIC_NAME
/

drop synonym DBA_HIST_SYSMETRIC_HISTORY
/

drop synonym CDB_HIST_SYSMETRIC_HISTORY
/

drop synonym DBA_HIST_SYSMETRIC_SUMMARY
/

drop synonym CDB_HIST_SYSMETRIC_SUMMARY
/

drop synonym DBA_HIST_CON_SYSMETRIC_HIST
/

drop synonym CDB_HIST_CON_SYSMETRIC_HIST
/

drop synonym DBA_HIST_CON_SYSMETRIC_SUMM
/

drop synonym CDB_HIST_CON_SYSMETRIC_SUMM
/

drop synonym DBA_HIST_SESSMETRIC_HISTORY
/

drop synonym CDB_HIST_SESSMETRIC_HISTORY
/

drop synonym DBA_HIST_FILEMETRIC_HISTORY
/

drop synonym CDB_HIST_FILEMETRIC_HISTORY
/

drop synonym DBA_HIST_WAITCLASSMET_HISTORY
/

drop synonym CDB_HIST_WAITCLASSMET_HISTORY
/

drop synonym DBA_HIST_DLM_MISC
/

drop synonym CDB_HIST_DLM_MISC
/

drop synonym DBA_HIST_CR_BLOCK_SERVER
/

drop synonym CDB_HIST_CR_BLOCK_SERVER
/

drop synonym DBA_HIST_CURRENT_BLOCK_SERVER
/

drop synonym CDB_HIST_CURRENT_BLOCK_SERVER
/

drop synonym DBA_HIST_INST_CACHE_TRANSFER
/

drop synonym CDB_HIST_INST_CACHE_TRANSFER
/

drop synonym DBA_HIST_PLAN_OPERATION_NAME
/

drop synonym CDB_HIST_PLAN_OPERATION_NAME
/

drop synonym DBA_HIST_PLAN_OPTION_NAME
/

drop synonym CDB_HIST_PLAN_OPTION_NAME
/

drop synonym DBA_HIST_SQLCOMMAND_NAME
/

drop synonym CDB_HIST_SQLCOMMAND_NAME
/

drop synonym DBA_HIST_TOPLEVELCALL_NAME
/

drop synonym CDB_HIST_TOPLEVELCALL_NAME
/

drop synonym DBA_HIST_ACTIVE_SESS_HISTORY
/

drop synonym CDB_HIST_ACTIVE_SESS_HISTORY
/

drop synonym DBA_HIST_ASH_SNAPSHOT
/

drop synonym CDB_HIST_ASH_SNAPSHOT
/

drop synonym DBA_HIST_TABLESPACE_STAT
/

drop synonym CDB_HIST_TABLESPACE_STAT
/

drop synonym DBA_HIST_LOG
/

drop synonym CDB_HIST_LOG
/

drop synonym DBA_HIST_MTTR_TARGET_ADVICE
/

drop synonym CDB_HIST_MTTR_TARGET_ADVICE
/

drop synonym DBA_HIST_TBSPC_SPACE_USAGE
/

drop synonym CDB_HIST_TBSPC_SPACE_USAGE
/

drop synonym DBA_HIST_SERVICE_NAME
/

drop synonym CDB_HIST_SERVICE_NAME
/

drop synonym DBA_HIST_SERVICE_STAT
/

drop synonym CDB_HIST_SERVICE_STAT
/

drop synonym DBA_HIST_SERVICE_WAIT_CLASS
/

drop synonym CDB_HIST_SERVICE_WAIT_CLASS
/

drop synonym DBA_HIST_SESS_TIME_STATS
/

drop synonym CDB_HIST_SESS_TIME_STATS
/

drop synonym DBA_HIST_STREAMS_CAPTURE
/

drop synonym CDB_HIST_STREAMS_CAPTURE
/

drop synonym DBA_HIST_CAPTURE
/

drop synonym CDB_HIST_CAPTURE
/

drop synonym DBA_HIST_STREAMS_APPLY_SUM
/

drop synonym CDB_HIST_STREAMS_APPLY_SUM
/

drop synonym DBA_HIST_APPLY_SUMMARY
/

drop synonym CDB_HIST_APPLY_SUMMARY
/

drop synonym DBA_HIST_BUFFERED_QUEUES
/

drop synonym CDB_HIST_BUFFERED_QUEUES
/

drop synonym DBA_HIST_BUFFERED_SUBSCRIBERS
/

drop synonym CDB_HIST_BUFFERED_SUBSCRIBERS
/

drop synonym DBA_HIST_RULE_SET
/

drop synonym CDB_HIST_RULE_SET
/

drop synonym DBA_HIST_PERSISTENT_QUEUES
/

drop synonym CDB_HIST_PERSISTENT_QUEUES
/

drop synonym DBA_HIST_PERSISTENT_SUBS
/

drop synonym CDB_HIST_PERSISTENT_SUBS
/

drop synonym DBA_HIST_SESS_SGA_STATS
/

drop synonym CDB_HIST_SESS_SGA_STATS
/

drop synonym DBA_HIST_REPLICATION_TBL_STATS
/

drop synonym CDB_HIST_REPLICATION_TBL_STATS
/

drop synonym DBA_HIST_REPLICATION_TXN_STATS
/

drop synonym CDB_HIST_REPLICATION_TXN_STATS
/

drop synonym DBA_HIST_IOSTAT_FUNCTION
/

drop synonym CDB_HIST_IOSTAT_FUNCTION
/

drop synonym DBA_HIST_IOSTAT_FUNCTION_NAME
/

drop synonym CDB_HIST_IOSTAT_FUNCTION_NAME
/

drop synonym DBA_HIST_IOSTAT_FILETYPE
/

drop synonym CDB_HIST_IOSTAT_FILETYPE
/

drop synonym DBA_HIST_IOSTAT_FILETYPE_NAME
/

drop synonym CDB_HIST_IOSTAT_FILETYPE_NAME
/

drop synonym DBA_HIST_IOSTAT_DETAIL
/

drop synonym CDB_HIST_IOSTAT_DETAIL
/

drop synonym DBA_HIST_RSRC_CONSUMER_GROUP
/

drop synonym CDB_HIST_RSRC_CONSUMER_GROUP
/

drop synonym DBA_HIST_RSRC_PLAN
/

drop synonym CDB_HIST_RSRC_PLAN
/

drop synonym DBA_HIST_RSRC_METRIC
/

drop synonym CDB_HIST_RSRC_METRIC
/

drop synonym DBA_HIST_RSRC_PDB_METRIC
/

drop synonym CDB_HIST_RSRC_PDB_METRIC
/

drop synonym DBA_HIST_CLUSTER_INTERCON
/

drop synonym CDB_HIST_CLUSTER_INTERCON
/

drop synonym DBA_HIST_MEM_DYNAMIC_COMP
/

drop synonym CDB_HIST_MEM_DYNAMIC_COMP
/

drop synonym DBA_HIST_IC_CLIENT_STATS
/

drop synonym CDB_HIST_IC_CLIENT_STATS
/

drop synonym DBA_HIST_IC_DEVICE_STATS
/

drop synonym CDB_HIST_IC_DEVICE_STATS
/

drop synonym DBA_HIST_INTERCONNECT_PINGS
/

drop synonym CDB_HIST_INTERCONNECT_PINGS
/

drop synonym DBA_HIST_DISPATCHER
/

drop synonym CDB_HIST_DISPATCHER
/

drop synonym DBA_HIST_SHARED_SERVER_SUMMARY
/

drop synonym CDB_HIST_SHARED_SERVER_SUMMARY
/

drop synonym DBA_HIST_DYN_REMASTER_STATS
/

drop synonym CDB_HIST_DYN_REMASTER_STATS
/

drop synonym DBA_HIST_LMS_STATS
/

drop synonym CDB_HIST_LMS_STATS
/

drop synonym DBA_HIST_PERSISTENT_QMN_CACHE
/

drop synonym CDB_HIST_PERSISTENT_QMN_CACHE
/

drop synonym DBA_HIST_PDB_INSTANCE
/

drop synonym CDB_HIST_PDB_INSTANCE
/

drop synonym DBA_HIST_PDB_IN_SNAP
/

drop synonym CDB_HIST_PDB_IN_SNAP
/

drop synonym DBA_HIST_CELL_CONFIG
/

drop synonym CDB_HIST_CELL_CONFIG
/

drop synonym DBA_HIST_CELL_CONFIG_DETAIL
/

drop synonym CDB_HIST_CELL_CONFIG_DETAIL
/

drop synonym DBA_HIST_ASM_DISKGROUP
/

drop synonym CDB_HIST_ASM_DISKGROUP
/

drop synonym DBA_HIST_ASM_DISKGROUP_STAT
/

drop synonym CDB_HIST_ASM_DISKGROUP_STAT
/

drop synonym DBA_HIST_ASM_BAD_DISK
/

drop synonym CDB_HIST_ASM_BAD_DISK
/

drop synonym DBA_HIST_CELL_NAME
/

drop synonym CDB_HIST_CELL_NAME
/

drop synonym DBA_HIST_CELL_DISKTYPE
/

drop synonym CDB_HIST_CELL_DISKTYPE
/

drop synonym DBA_HIST_CELL_DISK_NAME
/

drop synonym CDB_HIST_CELL_DISK_NAME
/

drop synonym DBA_HIST_CELL_GLOBAL_SUMMARY
/

drop synonym CDB_HIST_CELL_GLOBAL_SUMMARY
/

drop synonym DBA_HIST_CELL_DISK_SUMMARY
/

drop synonym CDB_HIST_CELL_DISK_SUMMARY
/

drop synonym DBA_HIST_CELL_METRIC_DESC
/

drop synonym CDB_HIST_CELL_METRIC_DESC
/

drop synonym DBA_HIST_CELL_IOREASON_NAME
/

drop synonym CDB_HIST_CELL_IOREASON_NAME
/

drop synonym DBA_HIST_CELL_GLOBAL
/

drop synonym CDB_HIST_CELL_GLOBAL
/

drop synonym DBA_HIST_CELL_IOREASON
/

drop synonym CDB_HIST_CELL_IOREASON
/

drop synonym DBA_HIST_CELL_DB
/

drop synonym CDB_HIST_CELL_DB
/

drop synonym DBA_HIST_CELL_OPEN_ALERTS
/

drop synonym CDB_HIST_CELL_OPEN_ALERTS
/

drop synonym DBA_HIST_IM_SEG_STAT
/

drop synonym CDB_HIST_IM_SEG_STAT
/

drop synonym DBA_HIST_IM_SEG_STAT_OBJ
/

drop synonym CDB_HIST_IM_SEG_STAT_OBJ
/

drop synonym DBA_HIST_WR_SETTINGS
/

drop synonym CDB_HIST_WR_SETTINGS
/

drop synonym DBA_HIST_PROCESS_WAITTIME
/

drop synonym CDB_HIST_PROCESS_WAITTIME
/

drop synonym DBA_HIST_ASM_DISK_STAT_SUMMARY
/

drop synonym CDB_HIST_ASM_DISK_STAT_SUMMARY
/

drop synonym DBA_HIST_TABLE_SETTINGS
/

drop synonym CDB_HIST_TABLE_SETTINGS
/

drop synonym DBMS_ADVISOR
/

drop synonym DBMS_ASSERT
/

drop synonym ODCICONST
/

drop synonym DBMS_ODCI
/

drop synonym DBMS_SCHEDULER
/

drop synonym JOBARG
/

drop synonym JOBARG_ARRAY
/

drop synonym JOB_DEFINITION
/

drop synonym JOB_DEFINITION_ARRAY
/

drop synonym JOBATTR
/

drop synonym JOBATTR_ARRAY
/

drop synonym JOB
/

drop synonym JOB_ARRAY
/

drop synonym SCHEDULER_BATCH_ERRORS
/

drop synonym DBA_SCHEDULER_PROGRAMS
/

drop synonym CDB_SCHEDULER_PROGRAMS
/

drop synonym USER_SCHEDULER_PROGRAMS
/

drop synonym ALL_SCHEDULER_PROGRAMS
/

drop synonym DBA_SCHEDULER_DESTS
/

drop synonym CDB_SCHEDULER_DESTS
/

drop synonym USER_SCHEDULER_DESTS
/

drop synonym ALL_SCHEDULER_DESTS
/

drop synonym DBA_SCHEDULER_EXTERNAL_DESTS
/

drop synonym CDB_SCHEDULER_EXTERNAL_DESTS
/

drop synonym ALL_SCHEDULER_EXTERNAL_DESTS
/

drop synonym DBA_SCHEDULER_DB_DESTS
/

drop synonym CDB_SCHEDULER_DB_DESTS
/

drop synonym USER_SCHEDULER_DB_DESTS
/

drop synonym ALL_SCHEDULER_DB_DESTS
/

drop synonym DBA_SCHEDULER_JOB_DESTS
/

drop synonym CDB_SCHEDULER_JOB_DESTS
/

drop synonym USER_SCHEDULER_JOB_DESTS
/

drop synonym ALL_SCHEDULER_JOB_DESTS
/

drop synonym DBA_SCHEDULER_JOBS
/

drop synonym CDB_SCHEDULER_JOBS
/

drop synonym USER_SCHEDULER_JOBS
/

drop synonym ALL_SCHEDULER_JOBS
/

drop synonym DBA_SCHEDULER_JOB_ROLES
/

drop synonym CDB_SCHEDULER_JOB_ROLES
/

drop synonym DBA_SCHEDULER_JOB_CLASSES
/

drop synonym CDB_SCHEDULER_JOB_CLASSES
/

drop synonym ALL_SCHEDULER_JOB_CLASSES
/

drop synonym DBA_SCHEDULER_WINDOWS
/

drop synonym CDB_SCHEDULER_WINDOWS
/

drop synonym ALL_SCHEDULER_WINDOWS
/

drop synonym DBA_SCHEDULER_PROGRAM_ARGS
/

drop synonym CDB_SCHEDULER_PROGRAM_ARGS
/

drop synonym USER_SCHEDULER_PROGRAM_ARGS
/

drop synonym ALL_SCHEDULER_PROGRAM_ARGS
/

drop synonym DBA_SCHEDULER_JOB_ARGS
/

drop synonym CDB_SCHEDULER_JOB_ARGS
/

drop synonym USER_SCHEDULER_JOB_ARGS
/

drop synonym ALL_SCHEDULER_JOB_ARGS
/

drop synonym CDB_SCHEDULER_JOB_LOG
/

drop synonym DBA_SCHEDULER_JOB_LOG
/

drop synonym DBA_SCHEDULER_JOB_RUN_DETAILS
/

drop synonym CDB_SCHEDULER_JOB_RUN_DETAILS
/

drop synonym USER_SCHEDULER_JOB_LOG
/

drop synonym USER_SCHEDULER_JOB_RUN_DETAILS
/

drop synonym ALL_SCHEDULER_JOB_LOG
/

drop synonym ALL_SCHEDULER_JOB_RUN_DETAILS
/

drop synonym CDB_SCHEDULER_WINDOW_LOG
/

drop synonym DBA_SCHEDULER_WINDOW_LOG
/

drop synonym DBA_SCHEDULER_WINDOW_DETAILS
/

drop synonym CDB_SCHEDULER_WINDOW_DETAILS
/

drop synonym ALL_SCHEDULER_WINDOW_LOG
/

drop synonym ALL_SCHEDULER_WINDOW_DETAILS
/

drop synonym DBA_SCHEDULER_WINDOW_GROUPS
/

drop synonym CDB_SCHEDULER_WINDOW_GROUPS
/

drop synonym ALL_SCHEDULER_WINDOW_GROUPS
/

drop synonym DBA_SCHEDULER_WINGROUP_MEMBERS
/

drop synonym CDB_SCHEDULER_WINGROUP_MEMBERS
/

drop synonym ALL_SCHEDULER_WINGROUP_MEMBERS
/

drop synonym DBA_SCHEDULER_GROUP_MEMBERS
/

drop synonym CDB_SCHEDULER_GROUP_MEMBERS
/

drop synonym USER_SCHEDULER_GROUP_MEMBERS
/

drop synonym ALL_SCHEDULER_GROUP_MEMBERS
/

drop synonym DBA_SCHEDULER_GROUPS
/

drop synonym CDB_SCHEDULER_GROUPS
/

drop synonym USER_SCHEDULER_GROUPS
/

drop synonym ALL_SCHEDULER_GROUPS
/

drop synonym DBA_SCHEDULER_SCHEDULES
/

drop synonym CDB_SCHEDULER_SCHEDULES
/

drop synonym USER_SCHEDULER_SCHEDULES
/

drop synonym ALL_SCHEDULER_SCHEDULES
/

drop synonym DBA_SCHEDULER_RUNNING_JOBS
/

drop synonym CDB_SCHEDULER_RUNNING_JOBS
/

drop synonym ALL_SCHEDULER_RUNNING_JOBS
/

drop synonym USER_SCHEDULER_RUNNING_JOBS
/

drop synonym DBA_SCHEDULER_REMOTE_DATABASES
/

drop synonym CDB_SCHEDULER_REMOTE_DATABASES
/

drop synonym ALL_SCHEDULER_REMOTE_DATABASES
/

drop synonym DBA_SCHEDULER_REMOTE_JOBSTATE
/

drop synonym CDB_SCHEDULER_REMOTE_JOBSTATE
/

drop synonym ALL_SCHEDULER_REMOTE_JOBSTATE
/

drop synonym USER_SCHEDULER_REMOTE_JOBSTATE
/

drop synonym DBA_SCHEDULER_GLOBAL_ATTRIBUTE
/

drop synonym CDB_SCHEDULER_GLOBAL_ATTRIBUTE
/

drop synonym ALL_SCHEDULER_GLOBAL_ATTRIBUTE
/

drop synonym DBA_SCHEDULER_CHAINS
/

drop synonym CDB_SCHEDULER_CHAINS
/

drop synonym USER_SCHEDULER_CHAINS
/

drop synonym ALL_SCHEDULER_CHAINS
/

drop synonym DBA_SCHEDULER_CHAIN_RULES
/

drop synonym CDB_SCHEDULER_CHAIN_RULES
/

drop synonym USER_SCHEDULER_CHAIN_RULES
/

drop synonym ALL_SCHEDULER_CHAIN_RULES
/

drop synonym DBA_SCHEDULER_CHAIN_STEPS
/

drop synonym CDB_SCHEDULER_CHAIN_STEPS
/

drop synonym USER_SCHEDULER_CHAIN_STEPS
/

drop synonym ALL_SCHEDULER_CHAIN_STEPS
/

drop synonym DBA_SCHEDULER_RUNNING_CHAINS
/

drop synonym CDB_SCHEDULER_RUNNING_CHAINS
/

drop synonym USER_SCHEDULER_RUNNING_CHAINS
/

drop synonym ALL_SCHEDULER_RUNNING_CHAINS
/

drop synonym DBA_SCHEDULER_CREDENTIALS
/

drop synonym CDB_SCHEDULER_CREDENTIALS
/

drop synonym USER_SCHEDULER_CREDENTIALS
/

drop synonym ALL_SCHEDULER_CREDENTIALS
/

drop synonym DBA_SCHEDULER_FILE_WATCHERS
/

drop synonym CDB_SCHEDULER_FILE_WATCHERS
/

drop synonym USER_SCHEDULER_FILE_WATCHERS
/

drop synonym ALL_SCHEDULER_FILE_WATCHERS
/

drop synonym DBA_SCHEDULER_NOTIFICATIONS
/

drop synonym CDB_SCHEDULER_NOTIFICATIONS
/

drop synonym USER_SCHEDULER_NOTIFICATIONS
/

drop synonym ALL_SCHEDULER_NOTIFICATIONS
/

drop synonym DBA_SCHEDULER_RESOURCES
/

drop synonym CDB_SCHEDULER_RESOURCES
/

drop synonym DBA_SCHEDULER_RSC_CONSTRAINTS
/

drop synonym CDB_SCHEDULER_RSC_CONSTRAINTS
/

drop synonym DBA_SCHEDULER_INCOMPATS
/

drop synonym CDB_SCHEDULER_INCOMPATS
/

drop synonym DBA_SCHEDULER_INCOMPAT_MEMBER
/

drop synonym CDB_SCHEDULER_INCOMPAT_MEMBER
/

drop synonym ALL_SCHEDULER_RESOURCES
/

drop synonym ALL_SCHEDULER_RSC_CONSTRAINTS
/

drop synonym ALL_SCHEDULER_INCOMPATS
/

drop synonym ALL_SCHEDULER_INCOMPAT_MEMBER
/

drop synonym USER_SCHEDULER_RESOURCES
/

drop synonym USER_SCHEDULER_RSC_CONSTRAINTS
/

drop synonym USER_SCHEDULER_INCOMPATS
/

drop synonym USER_SCHEDULER_INCOMPAT_MEMBER
/

drop synonym DBA_JOBS_RUNNING
/

drop synonym CDB_JOBS_RUNNING
/

drop synonym DBA_JOBS
/

drop synonym CDB_JOBS
/

drop synonym USER_JOBS
/

drop synonym ALL_JOBS
/

drop synonym DBA_SNAPSHOTS
/

drop synonym CDB_SNAPSHOTS
/

drop synonym ALL_SNAPSHOTS
/

drop synonym USER_SNAPSHOTS
/

drop synonym DBA_SNAPSHOT_LOGS
/

drop synonym CDB_SNAPSHOT_LOGS
/

drop synonym ALL_SNAPSHOT_LOGS
/

drop synonym USER_SNAPSHOT_LOGS
/

drop synonym DBA_RCHILD
/

drop synonym CDB_RCHILD
/

drop synonym DBA_RGROUP
/

drop synonym CDB_RGROUP
/

drop synonym DBA_REFRESH
/

drop synonym CDB_REFRESH
/

drop synonym ALL_REFRESH
/

drop synonym USER_REFRESH
/

drop synonym DBA_REFRESH_CHILDREN
/

drop synonym CDB_REFRESH_CHILDREN
/

drop synonym ALL_REFRESH_CHILDREN
/

drop synonym USER_REFRESH_CHILDREN
/

drop synonym DBA_REGISTERED_SNAPSHOTS
/

drop synonym CDB_REGISTERED_SNAPSHOTS
/

drop synonym ALL_REGISTERED_SNAPSHOTS
/

drop synonym USER_REGISTERED_SNAPSHOTS
/

drop synonym DBA_MVIEWS
/

drop synonym CDB_MVIEWS
/

drop synonym ALL_MVIEWS
/

drop synonym USER_MVIEWS
/

drop synonym DBA_SNAPSHOT_REFRESH_TIMES
/

drop synonym DBA_MVIEW_REFRESH_TIMES
/

drop synonym CDB_MVIEW_REFRESH_TIMES
/

drop synonym ALL_SNAPSHOT_REFRESH_TIMES
/

drop synonym ALL_MVIEW_REFRESH_TIMES
/

drop synonym USER_SNAPSHOT_REFRESH_TIMES
/

drop synonym USER_MVIEW_REFRESH_TIMES
/

drop synonym DBA_MVIEW_LOGS
/

drop synonym CDB_MVIEW_LOGS
/

drop synonym ALL_MVIEW_LOGS
/

drop synonym USER_MVIEW_LOGS
/

drop synonym DBA_BASE_TABLE_MVIEWS
/

drop synonym CDB_BASE_TABLE_MVIEWS
/

drop synonym ALL_BASE_TABLE_MVIEWS
/

drop synonym USER_BASE_TABLE_MVIEWS
/

drop synonym DBA_REGISTERED_MVIEWS
/

drop synonym CDB_REGISTERED_MVIEWS
/

drop synonym ALL_REGISTERED_MVIEWS
/

drop synonym USER_REGISTERED_MVIEWS
/

drop synonym DBA_SNAPSHOT_LOG_FILTER_COLS
/

drop synonym DBA_MVIEW_LOG_FILTER_COLS
/

drop synonym CDB_MVIEW_LOG_FILTER_COLS
/

drop synonym DBA_ZONEMAPS
/

drop synonym CDB_ZONEMAPS
/

drop synonym ALL_ZONEMAPS
/

drop synonym USER_ZONEMAPS
/

drop synonym DBA_ZONEMAP_MEASURES
/

drop synonym CDB_ZONEMAP_MEASURES
/

drop synonym ALL_ZONEMAP_MEASURES
/

drop synonym USER_ZONEMAP_MEASURES
/

drop synonym DBA_REDEFINITION_OBJECTS
/

drop synonym CDB_REDEFINITION_OBJECTS
/

drop synonym DBA_REDEFINITION_ERRORS
/

drop synonym CDB_REDEFINITION_ERRORS
/

drop synonym DBA_REDEFINITION_STATUS
/

drop synonym CDB_REDEFINITION_STATUS
/

drop synonym REWRITEMESSAGE
/

drop synonym REWRITEARRAYTYPE
/

drop synonym EXPLAINMVMESSAGE
/

drop synonym EXPLAINMVARRAYTYPE
/

drop synonym CANSYNCREFMESSAGE
/

drop synonym CANSYNCREFARRAYTYPE
/

drop synonym CDB_SR_GRP_STATUS_ALL
/

drop synonym CDB_SR_GRP_STATUS
/

drop synonym DBA_SR_GRP_STATUS_ALL
/

drop synonym DBA_SR_GRP_STATUS
/

drop synonym USER_SR_GRP_STATUS_ALL
/

drop synonym USER_SR_GRP_STATUS
/

drop synonym CDB_SR_OBJ_STATUS_ALL
/

drop synonym CDB_SR_OBJ_STATUS
/

drop synonym DBA_SR_OBJ_STATUS_ALL
/

drop synonym DBA_SR_OBJ_STATUS
/

drop synonym USER_SR_OBJ_STATUS_ALL
/

drop synonym USER_SR_OBJ_STATUS
/

drop synonym CDB_SR_OBJ_ALL
/

drop synonym CDB_SR_OBJ
/

drop synonym DBA_SR_OBJ_ALL
/

drop synonym DBA_SR_OBJ
/

drop synonym USER_SR_OBJ_ALL
/

drop synonym USER_SR_OBJ
/

drop synonym DBA_SR_STLOG_EXCEPTIONS
/

drop synonym CDB_SR_STLOG_EXCEPTIONS
/

drop synonym USER_SR_STLOG_EXCEPTIONS
/

drop synonym CDB_SR_STLOG_STATS
/

drop synonym DBA_SR_STLOG_STATS
/

drop synonym USER_SR_STLOG_STATS
/

drop synonym CDB_SR_PARTN_OPS
/

drop synonym DBA_SR_PARTN_OPS
/

drop synonym USER_SR_PARTN_OPS
/

drop synonym DBMS_XS_MTCACHE
/

drop synonym DBMS_XS_SIDP
/

drop synonym XS_PRINCIPAL
/

drop synonym XS$ROLE_GRANT_TYPE
/

drop synonym XS$ROLE_GRANT_LIST
/

drop synonym DBMS_STATS
/

drop synonym DBMS_SQLTUNE
/

drop synonym DBMS_AUTO_SQLTUNE
/

drop synonym DBMS_REPORT
/

drop synonym DBMS_OBJECTS_UTILS
/

drop synonym GET_OLDVERSION_HASHCODE
/

drop synonym GET_OLDVERSION_HASHCODE2
/

drop synonym DBMS_SQLQ
/

drop synonym UTL_INADDR
/

drop synonym UTL_SMTP
/

drop synonym UTL_URL
/

drop synonym UTL_ENCODE
/

drop synonym UTL_GDK
/

drop synonym UTL_CALL_STACK
/

drop synonym UTL_COMPRESS
/

drop synonym UTL_I18N
/

drop synonym UTL_LMS
/

drop synonym DBMS_WARNING
/

drop synonym USER_WARNING_SETTINGS
/

drop synonym ALL_WARNING_SETTINGS
/

drop synonym DBA_WARNING_SETTINGS
/

drop synonym CDB_WARNING_SETTINGS
/

drop synonym UTL_NLA_ARRAY_DBL
/

drop synonym UTL_NLA_ARRAY_FLT
/

drop synonym UTL_NLA_ARRAY_INT
/

drop synonym UTL_NLA
/

drop synonym DBMS_PDB_EXEC_SQL
/

drop synonym DBMS_PDB_IS_VALID_PATH
/

drop synonym DBMS_PDB_CHECK_LOCKDOWN
/

drop synonym DBMS_PDB
/

drop synonym DBMS_PDB_ALTER_SHARING
/

drop synonym DBMS_PDB_APP_CON
/

drop synonym DBMS_TRANSACTION
/

drop synonym DBMS_ROWID
/

drop synonym DBMS_PCLXUTIL
/

drop synonym DBMS_ERRLOG
/

drop synonym DBMS_SPACE
/

drop synonym DBMS_HEAT_MAP
/

drop synonym DBMS_SPACE_ALERT
/

drop synonym DBMS_APPLICATION_INFO
/

drop synonym DBMS_PIPE
/

drop synonym DBMS_DESCRIBE
/

drop synonym DBMS_JOB
/

drop synonym DBMS_STATS_INTERNAL_AGG
/

drop synonym DBMS_STATS_ADVISOR
/

drop synonym DBMS_STAT_FUNCS
/

drop synonym DBMS_DDL
/

drop synonym DBMS_EDITIONS_UTILITIES
/

drop synonym DBMS_PREPROCESSOR
/

drop synonym DBMS_DDL_INTERNAL
/

drop synonym DBMS_ZHELP
/

drop synonym DBMS_ZHELP_IR
/

drop synonym DBMS_MDX_ODBO
/

drop synonym DBMS_HIERARCHY
/

drop synonym DBMS_INDEX_UTL
/

drop synonym DBMS_PSP
/

drop synonym DBMS_FLASHBACK
/

drop synonym TIMESTAMP_TO_SCN
/

drop synonym SCN_TO_TIMESTAMP
/

drop synonym DBMS_FLASHBACK_ARCHIVE
/

drop synonym DBMS_XA
/

drop synonym DBMS_XA_XID
/

drop synonym DBMS_XA_XID_ARRAY
/

drop synonym DBMS_TRANSFORM
/

drop synonym DBMS_RULE_ADM
/

drop synonym DBMS_RULE
/

drop synonym DBMS_RULEADM_INTERNAL
/

drop synonym DBMS_RULE_INTERNAL
/

drop synonym DBMS_DEBUG
/

drop synonym DBMS_TRACE
/

drop synonym UTL_REF
/

drop synonym UTL_COLL
/

drop synonym DBMS_DISTRIBUTED_TRUST_ADMIN
/

drop synonym DBMS_RLS
/

drop synonym DBMS_XDS
/

drop synonym DBMS_CRYPTO
/

drop synonym DBMS_OBFUSCATION_TOOLKIT
/

drop synonym DBMS_SQLHASH
/

drop synonym DBMS_LOGMNR
/

drop synonym DBMS_LOGMNR_D
/

drop synonym DBMS_FGA
/

drop synonym AUD_PDB_LIST
/

drop synonym GET_AUD_PDB_LIST
/

drop synonym DBMS_AUDIT_MGMT
/

drop synonym DBMS_TYPE_UTILITY
/

drop synonym DBMS_RESUMABLE
/

drop synonym ORA_SPACE_ERROR_INFO
/

drop synonym DBMS_FBT
/

drop synonym DBMS_DG
/

drop synonym DBMS_SUMMARY
/

drop synonym DBMS_OLAP
/

drop synonym DBMS_DIMENSION
/

drop synonym DBMS_REDEFINITION
/

drop synonym DBMS_FILE_TRANSFER
/

drop synonym DBMS_STORAGE_MAP
/

drop synonym DBMS_FREQUENT_ITEMSET
/

drop synonym DBMS_SERVER_TRACE
/

drop synonym SYS_NT_COLLECT
/

drop synonym COLLECT
/

drop synonym DBMS_PROFILER
/

drop synonym DBMS_HPROF
/

drop synonym DBMS_PLSQL_CODE_COVERAGE
/

drop synonym DBMS_SERVICE
/

drop synonym DBMS_SERVICE_PRVT
/

drop synonym DBMS_CHANGE_NOTIFICATION
/

drop synonym DBMS_CQ_NOTIFICATION
/

drop synonym DBMS_XPLAN
/

drop synonym UTL_MATCH
/

drop synonym DBMS_DB_VERSION
/

drop synonym DBMS_RESULT_CACHE
/

drop synonym DBMS_RESULT_CACHE_API
/

drop synonym DBMS_AQ
/

drop synonym DBMS_AQADM
/

drop synonym DBMS_AQELM
/

drop synonym DBMS_AQ_EXP_QUEUE_TABLES
/

drop synonym DBMS_AQ_EXP_INDEX_TABLES
/

drop synonym DBMS_AQ_EXP_TIMEMGR_TABLES
/

drop synonym DBMS_AQ_EXP_HISTORY_TABLES
/

drop synonym DBMS_AQ_EXP_DEQUEUELOG_TABLES
/

drop synonym DBMS_AQ_EXP_CMT_TIME_TABLES
/

drop synonym DBMS_AQ_EXP_SIGNATURE_TABLES
/

drop synonym DBMS_AQ_EXP_SUBSCRIBER_TABLES
/

drop synonym DBMS_AQ_EXP_QUEUES
/

drop synonym DBMS_AQ_SYS_EXP_INTERNAL
/

drop synonym DBMS_AQ_SYS_EXP_ACTIONS
/

drop synonym DBMS_AQ_EXP_ZECURITY
/

drop synonym DBMS_AQ_SYS_IMP_INTERNAL
/

drop synonym DBMS_AQ_IMP_ZECURITY
/

drop synonym DBMS_AQ_IMP_INTERNAL
/

drop synonym ALERT_TYPE
/

drop synonym DBMS_SERVER_ALERT
/

drop synonym DBMS_MONITOR
/

drop synonym DBMS_HM
/

drop synonym DBMS_IR
/

drop synonym DBMS_LOBUTIL_INODE_T
/

drop synonym DBMS_LOBUTIL_LOBMAP_T
/

drop synonym DBMS_LOBUTIL_LOBEXTENT_T
/

drop synonym DBMS_LOBUTIL_LOBEXTENTS_T
/

drop synonym DBMS_LOBUTIL_DEDUPSET_T
/

drop synonym DBMS_LOBUTIL
/

drop synonym DBMS_ADDM
/

drop synonym DBMS_TRANSFORM_EXIMP
/

drop synonym DBMS_RMIN_SYS
/

drop synonym DBMS_RMIN
/

drop synonym DBMS_RESOURCE_MANAGER
/

drop synonym DBMS_RESOURCE_MANAGER_PRIVS
/

drop synonym DBMS_RMGR_PLAN_EXPORT
/

drop synonym DBMS_RMGR_GROUP_EXPORT
/

drop synonym DBMS_RMGR_PACT_EXPORT
/

drop synonym DBMS_METADATA
/

drop synonym DBMS_METADATA_BUILD
/

drop synonym DBMS_METADATA_DPBUILD
/

drop synonym DBMS_METADATA_DIFF
/

drop synonym KU$_WORKERSTATUS1010
/

drop synonym KU$_WORKERSTATUS1020
/

drop synonym KU$_WORKERSTATUS1120
/

drop synonym KU$_WORKERSTATUS1210
/

drop synonym KU$_WORKERSTATUS1220
/

drop synonym KU$_WORKERSTATUS
/

drop synonym KU$_WORKERSTATUSLIST1010
/

drop synonym KU$_WORKERSTATUSLIST1020
/

drop synonym KU$_WORKERSTATUSLIST1120
/

drop synonym KU$_WORKERSTATUSLIST1210
/

drop synonym KU$_WORKERSTATUSLIST1220
/

drop synonym KU$_WORKERSTATUSLIST
/

drop synonym KU$_DUMPFILE1010
/

drop synonym KU$_DUMPFILE1020
/

drop synonym KU$_DUMPFILE
/

drop synonym KU$_DUMPFILESET1010
/

drop synonym KU$_DUMPFILESET1020
/

drop synonym KU$_DUMPFILESET
/

drop synonym KU$_LOGLINE1010
/

drop synonym KU$_LOGLINE1020
/

drop synonym KU$_LOGLINE
/

drop synonym KU$_LOGENTRY1010
/

drop synonym KU$_LOGENTRY1020
/

drop synonym KU$_LOGENTRY
/

drop synonym KU$_JOBSTATUS1010
/

drop synonym KU$_JOBSTATUS1020
/

drop synonym KU$_JOBSTATUS1120
/

drop synonym KU$_JOBSTATUS1210
/

drop synonym KU$_JOBSTATUS1220
/

drop synonym KU$_JOBSTATUS
/

drop synonym KU$_PARAMVALUE1010
/

drop synonym KU$_PARAMVALUE1020
/

drop synonym KU$_PARAMVALUE
/

drop synonym KU$_PARAMVALUES1010
/

drop synonym KU$_PARAMVALUES1020
/

drop synonym KU$_PARAMVALUES
/

drop synonym KU$_JOBDESC1010
/

drop synonym KU$_JOBDESC1020
/

drop synonym KU$_JOBDESC1210
/

drop synonym KU$_JOBDESC1220
/

drop synonym KU$_JOBDESC
/

drop synonym KU$_STATUS1010
/

drop synonym KU$_STATUS1020
/

drop synonym KU$_STATUS1120
/

drop synonym KU$_STATUS1210
/

drop synonym KU$_STATUS1220
/

drop synonym KU$_STATUS
/

drop synonym KU$_DUMPFILE_ITEM
/

drop synonym KU$_DUMPFILE_INFO
/

drop synonym DBMS_DATAPUMP
/

drop synonym DBMS_TDE_TOOLKIT
/

drop synonym PRIVATE_JDBC
/

drop synonym DBMS_SERVER_ALERT_EXPORT
/

drop synonym DBMS_MANAGEMENT_BOOTSTRAP
/

drop synonym DBMS_WORKLOAD_REPOSITORY
/

drop synonym DBMS_AWR_WAREHOUSE_SERVER
/

drop synonym DBMS_AWR_WAREHOUSE_SOURCE
/

drop synonym DBMS_UMF
/

drop synonym PRVT_EMX
/

drop synonym DBMS_PERF
/

drop synonym PRVTEMX_SQL
/

drop synonym DBMS_ASH_INTERNAL
/

drop synonym ASHVIEWER
/

drop synonym DBMS_ASH
/

drop synonym PRVT_ASH_OMX
/

drop synonym DBMS_WORKLOAD_CAPTURE
/

drop synonym DBMS_WORKLOAD_REPLAY
/

drop synonym DBMS_FEATURE_USAGE_REPORT
/

drop synonym DBMS_UNDO_ADV
/

drop synonym DBMS_SPM
/

drop synonym DBMS_LCR
/

drop synonym DBMS_STREAMS_TABLESPACE_ADM
/

drop synonym DBMS_STREAMS
/

drop synonym DBMS_STREAMS_ADM
/

drop synonym DBMS_STREAMS_AUTH
/

drop synonym DBMS_APPLY_ADM
/

drop synonym DBMS_CAPTURE_ADM
/

drop synonym DBMS_PROPAGATION_ADM
/

drop synonym DBMS_FILE_GROUP
/

drop synonym DBMS_COMPARISON
/

drop synonym DBMS_XSTREAM_ADM
/

drop synonym DBMS_XSTREAM_AUTH
/

drop synonym DBMS_GOLDENGATE_ADM
/

drop synonym DBMS_GOLDENGATE_AUTH
/

drop synonym DBMS_STREAMS_LCR_INT
/

drop synonym DBMS_STREAMS_ADM_IVK
/

drop synonym DBMS_APPLY_POSITION
/

drop synonym DBMS_STREAMS_RPC
/

drop synonym DBMS_CAPTURE_SWITCH_ADM
/

drop synonym DBMS_XSTREAM_AUTH_IVK
/

drop synonym DBMS_XSTREAM_GG
/

drop synonym DBMS_XSTREAM_GG_ADM
/

drop synonym DBMS_SQLSET
/

drop synonym DBMS_SQLPA
/

drop synonym DBMS_AUTO_REPORT
/

drop synonym DBMS_RAT_MASK
/

drop synonym DBMS_SQLDIAG
/

drop synonym DBMS_REPCAT_MIG
/

drop synonym DBMS_REPUTIL
/

drop synonym DBMS_CACHEUTIL
/

drop synonym DBMS_DST
/

drop synonym DBMS_COMPRESSION
/

drop synonym DBMS_ILM
/

drop synonym DBMS_ILM_ADMIN
/

drop synonym DBMS_PARALLEL_EXECUTE
/

drop synonym DBMS_DBFS_CONTENT
/

drop synonym DBMS_DBFS_CONTENT_ADMIN
/

drop synonym DBMS_FUSE
/

drop synonym DBMS_FUSE_PUBLIC
/

drop synonym DBMS_DBFS_SFS
/

drop synonym DBMS_DBFS_SFS_ADMIN
/

drop synonym DBMS_DBFS_HS
/

drop synonym DBMS_DNFS
/

drop synonym DBMS_ADR
/

drop synonym DBMS_ADR_APP
/

drop synonym DBMS_XS_NSATTR
/

drop synonym DBMS_XS_NSATTRLIST
/

drop synonym DBMS_XS_SESSIONS
/

drop synonym DBMS_REDACT
/

drop synonym DBMS_SQL_TRANSLATOR
/

drop synonym DBMS_APP_CONT
/

drop synonym DBMS_APP_CONT_ADMIN
/

drop synonym DBMS_APP_CONT_PRVT
/

drop synonym DBMS_TG_DBG
/

drop synonym DBMS_SPD
/

drop synonym DBMS_FS
/

drop synonym DBMS_SQL_MONITOR
/

drop synonym DBMS_PRIVILEGE_CAPTURE
/

drop synonym DBMS_PRIV_CAPTURE
/

drop synonym DBMS_PART
/

drop synonym DBMS_ROLLING
/

drop synonym DBMS_TSDP_MANAGE
/

drop synonym TSDP$VALIDATION_CHECK
/

drop synonym DBMS_TSDP_PROTECT
/

drop synonym DBMS_INMEMORY
/

drop synonym DBMS_INMEMORY_ADMIN
/

drop synonym DBMS_TF
/

drop synonym DBMS_TNS
/

drop synonym CDB_APPLICATIONS
/

drop synonym CDB_APP_PATCHES
/

drop synonym CDB_APP_VERSIONS
/

drop synonym CDB_APP_STATEMENTS
/

drop synonym CDB_APP_ERRORS
/

drop synonym CDB_APP_PDB_STATUS
/

drop synonym DBMS_SCHED_PROGRAM_EXPORT
/

drop synonym DBMS_SCHED_JOB_EXPORT
/

drop synonym DBMS_SCHED_WINDOW_EXPORT
/

drop synonym DBMS_SCHED_WINGRP_EXPORT
/

drop synonym DBMS_SCHED_CLASS_EXPORT
/

drop synonym DBMS_SCHED_SCHEDULE_EXPORT
/

drop synonym DBMS_SCHED_CHAIN_EXPORT
/

drop synonym DBMS_SCHED_CONSTRAINT_EXPORT
/

drop synonym DBMS_SCHED_CREDENTIAL_EXPORT
/

drop synonym DBMS_SCHED_FILE_WATCHER_EXPORT
/

drop synonym DBMS_SCHED_ATTRIBUTE_EXPORT
/

drop synonym DBMS_SCHED_EXPORT_CALLOUTS
/

drop synonym DBMS_SCHED_ARGUMENT_IMPORT
/

drop synonym OUTLN_PKG
/

drop synonym OUTLINE
/

drop synonym DBMS_OUTLN
/

drop synonym DBMS_OUTLN_INTERNAL
/

drop synonym DBMS_MEMOPTIMIZE
/

drop synonym DBMS_MEMOPTIMIZE_ADMIN
/

drop synonym DBMS_AUTO_INDEX
/

drop synonym DBA_SQL_PLAN_DIRECTIVES
/

drop synonym CDB_SQL_PLAN_DIRECTIVES
/

drop synonym DBA_SQL_PLAN_DIR_OBJECTS
/

drop synonym CDB_SQL_PLAN_DIR_OBJECTS
/

drop synonym USER_TAB_COL_STATISTICS
/

drop synonym ALL_TAB_COL_STATISTICS
/

drop synonym DBA_TAB_COL_STATISTICS
/

drop synonym CDB_TAB_COL_STATISTICS
/

drop synonym USER_PART_COL_STATISTICS
/

drop synonym ALL_PART_COL_STATISTICS
/

drop synonym DBA_PART_COL_STATISTICS
/

drop synonym CDB_PART_COL_STATISTICS
/

drop synonym ALL_STAT_EXTENSIONS
/

drop synonym DBA_STAT_EXTENSIONS
/

drop synonym CDB_STAT_EXTENSIONS
/

drop synonym USER_STAT_EXTENSIONS
/

drop synonym ALL_TAB_STATISTICS
/

drop synonym DBA_TAB_STATISTICS
/

drop synonym CDB_TAB_STATISTICS
/

drop synonym USER_TAB_STATISTICS
/

drop synonym ALL_IND_STATISTICS
/

drop synonym DBA_IND_STATISTICS
/

drop synonym CDB_IND_STATISTICS
/

drop synonym USER_IND_STATISTICS
/

drop synonym USER_TAB_HISTOGRAMS
/

drop synonym USER_HISTOGRAMS
/

drop synonym ALL_TAB_HISTOGRAMS
/

drop synonym ALL_HISTOGRAMS
/

drop synonym DBA_TAB_HISTOGRAMS
/

drop synonym CDB_TAB_HISTOGRAMS
/

drop synonym DBA_HISTOGRAMS
/

drop synonym USER_PART_HISTOGRAMS
/

drop synonym ALL_PART_HISTOGRAMS
/

drop synonym DBA_PART_HISTOGRAMS
/

drop synonym CDB_PART_HISTOGRAMS
/

drop synonym USER_SUBPART_HISTOGRAMS
/

drop synonym ALL_SUBPART_HISTOGRAMS
/

drop synonym DBA_SUBPART_HISTOGRAMS
/

drop synonym CDB_SUBPART_HISTOGRAMS
/

drop synonym ALL_COL_PENDING_STATS
/

drop synonym DBA_COL_PENDING_STATS
/

drop synonym CDB_COL_PENDING_STATS
/

drop synonym USER_COL_PENDING_STATS
/

drop synonym ALL_TAB_HISTGRM_PENDING_STATS
/

drop synonym DBA_TAB_HISTGRM_PENDING_STATS
/

drop synonym CDB_TAB_HISTGRM_PENDING_STATS
/

drop synonym USER_TAB_HISTGRM_PENDING_STATS
/

drop synonym USER_EXPRESSION_STATISTICS
/

drop synonym ALL_EXPRESSION_STATISTICS
/

drop synonym DBA_EXPRESSION_STATISTICS
/

drop synonym CDB_EXPRESSION_STATISTICS
/

drop synonym SQT_TAB_STATISTICS
/

drop synonym SQT_CORRECT_BIT
/

drop synonym SQT_TAB_COL_STATISTICS
/

drop synonym DBA_PENDING_TRANSACTIONS
/

drop synonym CDB_PENDING_TRANSACTIONS
/

drop synonym V$BACKUP_FILES
/

drop synonym V$RESTORE_RANGE
/

drop synonym V$DISK_RESTORE_RANGE
/

drop synonym V$SBT_RESTORE_RANGE
/

drop synonym V$RMAN_BACKUP_SUBJOB_DETAILS
/

drop synonym V$RMAN_BACKUP_JOB_DETAILS
/

drop synonym V$BACKUP_SET_DETAILS
/

drop synonym V$BACKUP_PIECE_DETAILS
/

drop synonym V$BACKUP_COPY_DETAILS
/

drop synonym V$PROXY_COPY_DETAILS
/

drop synonym V$PROXY_ARCHIVELOG_DETAILS
/

drop synonym V$BACKUP_DATAFILE_DETAILS
/

drop synonym V$BACKUP_CONTROLFILE_DETAILS
/

drop synonym V$BACKUP_ARCHIVELOG_DETAILS
/

drop synonym V$BACKUP_SPFILE_DETAILS
/

drop synonym V$BACKUP_SET_SUMMARY
/

drop synonym V$BACKUP_DATAFILE_SUMMARY
/

drop synonym V$BACKUP_CONTROLFILE_SUMMARY
/

drop synonym V$BACKUP_ARCHIVELOG_SUMMARY
/

drop synonym V$BACKUP_SPFILE_SUMMARY
/

drop synonym V$BACKUP_COPY_SUMMARY
/

drop synonym V$PROXY_COPY_SUMMARY
/

drop synonym V$PROXY_ARCHIVELOG_SUMMARY
/

drop synonym V$UNUSABLE_BACKUPFILE_DETAILS
/

drop synonym V$RMAN_BACKUP_TYPE
/

drop synonym V$RMAN_ENCRYPTION_ALGORITHMS
/

drop synonym ORA_SYSEVENT
/

drop synonym ORA_DICT_OBJ_TYPE
/

drop synonym ORA_DICT_OBJ_OWNER
/

drop synonym ORA_DICT_OBJ_NAME
/

drop synonym ORA_DATABASE_NAME
/

drop synonym ORA_INSTANCE_NUM
/

drop synonym ORA_LOGIN_USER
/

drop synonym ORA_IS_SERVERERROR
/

drop synonym ORA_SERVER_ERROR
/

drop synonym ORA_DES_ENCRYPTED_PASSWORD
/

drop synonym ORA_IS_ALTER_COLUMN
/

drop synonym ORA_IS_DROP_COLUMN
/

drop synonym ORA_GRANTEE
/

drop synonym ORA_REVOKEE
/

drop synonym ORA_PRIVILEGE_LIST
/

drop synonym ORA_WITH_GRANT_OPTION
/

drop synonym ORA_DICT_OBJ_OWNER_LIST
/

drop synonym ORA_DICT_OBJ_NAME_LIST
/

drop synonym ORA_IS_CREATING_NESTED_TABLE
/

drop synonym ORA_CLIENT_IP_ADDRESS
/

drop synonym ORA_SQL_TXT
/

drop synonym ORA_ORIGINAL_SQL_TXT
/

drop synonym ORA_SERVER_ERROR_MSG
/

drop synonym ORA_SERVER_ERROR_DEPTH
/

drop synonym ORA_SERVER_ERROR_NUM_PARAMS
/

drop synonym ORA_PARTITION_POS
/

drop synonym ORA_SERVER_ERROR_PARAM
/

drop synonym DBMS_RANDOM
/

drop synonym DBMS_DEBUG_JDWP
/

drop synonym CDB_AWS
/

drop synonym CDB_AW_PS
/

drop synonym DBA_AWS
/

drop synonym DBA_AW_PS
/

drop synonym USER_AWS
/

drop synonym USER_AW_PS
/

drop synonym ALL_AWS
/

drop synonym ALL_AW_PS
/

drop synonym DBA_CUBES
/

drop synonym CDB_CUBES
/

drop synonym ALL_CUBES
/

drop synonym USER_CUBES
/

drop synonym USER_CUBE_SUB_PARTITION_LEVELS
/

drop synonym DBA_CUBE_SUB_PARTITION_LEVELS
/

drop synonym CDB_CUBE_SUB_PARTITION_LEVELS
/

drop synonym ALL_CUBE_SUB_PARTITION_LEVELS
/

drop synonym DBA_CUBE_DIMENSIONALITY
/

drop synonym CDB_CUBE_DIMENSIONALITY
/

drop synonym ALL_CUBE_DIMENSIONALITY
/

drop synonym USER_CUBE_DIMENSIONALITY
/

drop synonym DBA_CUBE_MEASURES
/

drop synonym CDB_CUBE_MEASURES
/

drop synonym ALL_CUBE_MEASURES
/

drop synonym USER_CUBE_MEASURES
/

drop synonym DBA_CUBE_DIMENSIONS
/

drop synonym CDB_CUBE_DIMENSIONS
/

drop synonym ALL_CUBE_DIMENSIONS
/

drop synonym USER_CUBE_DIMENSIONS
/

drop synonym DBA_CUBE_HIERARCHIES
/

drop synonym CDB_CUBE_HIERARCHIES
/

drop synonym ALL_CUBE_HIERARCHIES
/

drop synonym USER_CUBE_HIERARCHIES
/

drop synonym DBA_CUBE_HIER_LEVELS
/

drop synonym CDB_CUBE_HIER_LEVELS
/

drop synonym ALL_CUBE_HIER_LEVELS
/

drop synonym USER_CUBE_HIER_LEVELS
/

drop synonym DBA_CUBE_DIM_LEVELS
/

drop synonym CDB_CUBE_DIM_LEVELS
/

drop synonym ALL_CUBE_DIM_LEVELS
/

drop synonym USER_CUBE_DIM_LEVELS
/

drop synonym DBA_CUBE_ATTRIBUTES
/

drop synonym CDB_CUBE_ATTRIBUTES
/

drop synonym ALL_CUBE_ATTRIBUTES
/

drop synonym USER_CUBE_ATTRIBUTES
/

drop synonym DBA_CUBE_ATTR_VISIBILITY
/

drop synonym CDB_CUBE_ATTR_VISIBILITY
/

drop synonym ALL_CUBE_ATTR_VISIBILITY
/

drop synonym USER_CUBE_ATTR_VISIBILITY
/

drop synonym DBA_CUBE_DIM_MODELS
/

drop synonym CDB_CUBE_DIM_MODELS
/

drop synonym ALL_CUBE_DIM_MODELS
/

drop synonym USER_CUBE_DIM_MODELS
/

drop synonym DBA_CUBE_CALCULATED_MEMBERS
/

drop synonym CDB_CUBE_CALCULATED_MEMBERS
/

drop synonym ALL_CUBE_CALCULATED_MEMBERS
/

drop synonym USER_CUBE_CALCULATED_MEMBERS
/

drop synonym DBA_CUBE_VIEWS
/

drop synonym CDB_CUBE_VIEWS
/

drop synonym ALL_CUBE_VIEWS
/

drop synonym USER_CUBE_VIEWS
/

drop synonym DBA_CUBE_VIEW_COLUMNS
/

drop synonym CDB_CUBE_VIEW_COLUMNS
/

drop synonym ALL_CUBE_VIEW_COLUMNS
/

drop synonym USER_CUBE_VIEW_COLUMNS
/

drop synonym DBA_CUBE_DIM_VIEWS
/

drop synonym CDB_CUBE_DIM_VIEWS
/

drop synonym ALL_CUBE_DIM_VIEWS
/

drop synonym USER_CUBE_DIM_VIEWS
/

drop synonym DBA_CUBE_DIM_VIEW_COLUMNS
/

drop synonym CDB_CUBE_DIM_VIEW_COLUMNS
/

drop synonym ALL_CUBE_DIM_VIEW_COLUMNS
/

drop synonym USER_CUBE_DIM_VIEW_COLUMNS
/

drop synonym DBA_CUBE_HIER_VIEWS
/

drop synonym CDB_CUBE_HIER_VIEWS
/

drop synonym ALL_CUBE_HIER_VIEWS
/

drop synonym USER_CUBE_HIER_VIEWS
/

drop synonym DBA_CUBE_HIER_VIEW_COLUMNS
/

drop synonym CDB_CUBE_HIER_VIEW_COLUMNS
/

drop synonym ALL_CUBE_HIER_VIEW_COLUMNS
/

drop synonym USER_CUBE_HIER_VIEW_COLUMNS
/

drop synonym DBA_MEASURE_FOLDERS
/

drop synonym CDB_MEASURE_FOLDERS
/

drop synonym ALL_MEASURE_FOLDERS
/

drop synonym USER_MEASURE_FOLDERS
/

drop synonym DBA_MEASURE_FOLDER_CONTENTS
/

drop synonym CDB_MEASURE_FOLDER_CONTENTS
/

drop synonym ALL_MEASURE_FOLDER_CONTENTS
/

drop synonym USER_MEASURE_FOLDER_CONTENTS
/

drop synonym USER_MEASURE_FOLDER_SUBFOLDERS
/

drop synonym DBA_MEASURE_FOLDER_SUBFOLDERS
/

drop synonym CDB_MEASURE_FOLDER_SUBFOLDERS
/

drop synonym ALL_MEASURE_FOLDER_SUBFOLDERS
/

drop synonym DBA_CUBE_BUILD_PROCESSES
/

drop synonym CDB_CUBE_BUILD_PROCESSES
/

drop synonym ALL_CUBE_BUILD_PROCESSES
/

drop synonym USER_CUBE_BUILD_PROCESSES
/

drop synonym DBA_CUBE_MAPPINGS
/

drop synonym CDB_CUBE_MAPPINGS
/

drop synonym ALL_CUBE_MAPPINGS
/

drop synonym USER_CUBE_MAPPINGS
/

drop synonym DBA_CUBE_MEAS_MAPPINGS
/

drop synonym CDB_CUBE_MEAS_MAPPINGS
/

drop synonym ALL_CUBE_MEAS_MAPPINGS
/

drop synonym USER_CUBE_MEAS_MAPPINGS
/

drop synonym DBA_CUBE_DIMNL_MAPPINGS
/

drop synonym CDB_CUBE_DIMNL_MAPPINGS
/

drop synonym ALL_CUBE_DIMNL_MAPPINGS
/

drop synonym USER_CUBE_DIMNL_MAPPINGS
/

drop synonym DBA_CUBE_DIM_MAPPINGS
/

drop synonym CDB_CUBE_DIM_MAPPINGS
/

drop synonym ALL_CUBE_DIM_MAPPINGS
/

drop synonym USER_CUBE_DIM_MAPPINGS
/

drop synonym DBA_CUBE_ATTR_MAPPINGS
/

drop synonym CDB_CUBE_ATTR_MAPPINGS
/

drop synonym ALL_CUBE_ATTR_MAPPINGS
/

drop synonym USER_CUBE_ATTR_MAPPINGS
/

drop synonym DBA_CUBE_DESCRIPTIONS
/

drop synonym CDB_CUBE_DESCRIPTIONS
/

drop synonym ALL_CUBE_DESCRIPTIONS
/

drop synonym USER_CUBE_DESCRIPTIONS
/

drop synonym DBA_CUBE_CLASSIFICATIONS
/

drop synonym CDB_CUBE_CLASSIFICATIONS
/

drop synonym ALL_CUBE_CLASSIFICATIONS
/

drop synonym USER_CUBE_CLASSIFICATIONS
/

drop synonym DBA_CUBE_ATTR_UNIQUE_KEYS
/

drop synonym CDB_CUBE_ATTR_UNIQUE_KEYS
/

drop synonym ALL_CUBE_ATTR_UNIQUE_KEYS
/

drop synonym USER_CUBE_ATTR_UNIQUE_KEYS
/

drop synonym USER_CUBE_NAMED_BUILD_SPECS
/

drop synonym DBA_CUBE_NAMED_BUILD_SPECS
/

drop synonym CDB_CUBE_NAMED_BUILD_SPECS
/

drop synonym ALL_CUBE_NAMED_BUILD_SPECS
/

drop synonym USER_METADATA_PROPERTIES
/

drop synonym ALL_METADATA_PROPERTIES
/

drop synonym DBA_METADATA_PROPERTIES
/

drop synonym CDB_METADATA_PROPERTIES
/

drop synonym DBA_CUBE_DEPENDENCIES
/

drop synonym CDB_CUBE_DEPENDENCIES
/

drop synonym ALL_CUBE_DEPENDENCIES
/

drop synonym USER_CUBE_DEPENDENCIES
/

drop synonym DBMS_SNAPSHOT
/

drop synonym DBMS_MVIEW
/

drop synonym DBMS_REFRESH
/

drop synonym USER_QUEUE_SUBSCRIBERS
/

drop synonym ALL_QUEUE_SUBSCRIBERS
/

drop synonym DBA_QUEUE_SUBSCRIBERS
/

drop synonym CDB_QUEUE_SUBSCRIBERS
/

drop synonym "_ALL_QUEUE_CACHED_MESSAGES"
/

drop synonym AQ$_GET_CACHE_MSGBM
/

drop synonym DBMS_AQJMS
/

drop synonym DBMS_AQIN
/

drop synonym DBMS_AQADM_SYSCALLS
/

drop synonym DBMS_AQADM_VAR
/

drop synonym DBA_ADVISOR_DEFINITIONS
/

drop synonym CDB_ADVISOR_DEFINITIONS
/

drop synonym DBA_ADVISOR_COMMANDS
/

drop synonym CDB_ADVISOR_COMMANDS
/

drop synonym DBA_ADVISOR_OBJECT_TYPES
/

drop synonym CDB_ADVISOR_OBJECT_TYPES
/

drop synonym DBA_ADVISOR_USAGE
/

drop synonym CDB_ADVISOR_USAGE
/

drop synonym DBA_ADVISOR_EXECUTION_TYPES
/

drop synonym CDB_ADVISOR_EXECUTION_TYPES
/

drop synonym DBA_ADVISOR_TASKS
/

drop synonym USER_ADVISOR_TASKS
/

drop synonym CDB_ADVISOR_TASKS
/

drop synonym DBA_ADVISOR_TEMPLATES
/

drop synonym USER_ADVISOR_TEMPLATES
/

drop synonym CDB_ADVISOR_TEMPLATES
/

drop synonym DBA_ADVISOR_LOG
/

drop synonym USER_ADVISOR_LOG
/

drop synonym CDB_ADVISOR_LOG
/

drop synonym DBA_ADVISOR_DEF_PARAMETERS
/

drop synonym CDB_ADVISOR_DEF_PARAMETERS
/

drop synonym DBA_ADVISOR_PARAMETERS
/

drop synonym USER_ADVISOR_PARAMETERS
/

drop synonym CDB_ADVISOR_PARAMETERS
/

drop synonym DBA_ADVISOR_PARAMETERS_PROJ
/

drop synonym CDB_ADVISOR_PARAMETERS_PROJ
/

drop synonym DBA_ADVISOR_EXECUTIONS
/

drop synonym USER_ADVISOR_EXECUTIONS
/

drop synonym CDB_ADVISOR_EXECUTIONS
/

drop synonym DBA_ADVISOR_EXEC_PARAMETERS
/

drop synonym USER_ADVISOR_EXEC_PARAMETERS
/

drop synonym CDB_ADVISOR_EXEC_PARAMETERS
/

drop synonym DBA_ADVISOR_OBJECTS
/

drop synonym CDB_ADVISOR_OBJECTS
/

drop synonym USER_ADVISOR_OBJECTS
/

drop synonym DBA_ADVISOR_FINDINGS
/

drop synonym USER_ADVISOR_FINDINGS
/

drop synonym CDB_ADVISOR_FINDINGS
/

drop synonym DBA_ADVISOR_FDG_BREAKDOWN
/

drop synonym USER_ADVISOR_FDG_BREAKDOWN
/

drop synonym CDB_ADVISOR_FDG_BREAKDOWN
/

drop synonym DBA_ADVISOR_RECOMMENDATIONS
/

drop synonym USER_ADVISOR_RECOMMENDATIONS
/

drop synonym CDB_ADVISOR_RECOMMENDATIONS
/

drop synonym DBA_ADVISOR_ACTIONS
/

drop synonym USER_ADVISOR_ACTIONS
/

drop synonym CDB_ADVISOR_ACTIONS
/

drop synonym DBA_ADVISOR_RATIONALE
/

drop synonym USER_ADVISOR_RATIONALE
/

drop synonym CDB_ADVISOR_RATIONALE
/

drop synonym DBA_ADVISOR_DIR_DEFINITIONS
/

drop synonym CDB_ADVISOR_DIR_DEFINITIONS
/

drop synonym DBA_ADVISOR_DIR_INSTANCES
/

drop synonym CDB_ADVISOR_DIR_INSTANCES
/

drop synonym DBA_ADVISOR_DIR_TASK_INST
/

drop synonym USER_ADVISOR_DIR_TASK_INST
/

drop synonym CDB_ADVISOR_DIR_TASK_INST
/

drop synonym DBA_ADVISOR_JOURNAL
/

drop synonym USER_ADVISOR_JOURNAL
/

drop synonym CDB_ADVISOR_JOURNAL
/

drop synonym DBA_ADVISOR_FINDING_NAMES
/

drop synonym CDB_ADVISOR_FINDING_NAMES
/

drop synonym DBA_ADVISOR_SQLSTATS
/

drop synonym CDB_ADVISOR_SQLSTATS
/

drop synonym USER_ADVISOR_SQLSTATS
/

drop synonym DBA_ADVISOR_SQLPLANS
/

drop synonym CDB_ADVISOR_SQLPLANS
/

drop synonym USER_ADVISOR_SQLPLANS
/

drop synonym DBA_ADDM_TASKS
/

drop synonym USER_ADDM_TASKS
/

drop synonym CDB_ADDM_TASKS
/

drop synonym DBA_ADDM_INSTANCES
/

drop synonym USER_ADDM_INSTANCES
/

drop synonym CDB_ADDM_INSTANCES
/

drop synonym DBA_ADDM_FINDINGS
/

drop synonym USER_ADDM_FINDINGS
/

drop synonym CDB_ADDM_FINDINGS
/

drop synonym DBA_ADDM_FDG_BREAKDOWN
/

drop synonym USER_ADDM_FDG_BREAKDOWN
/

drop synonym CDB_ADDM_FDG_BREAKDOWN
/

drop synonym DBA_ADDM_SYSTEM_DIRECTIVES
/

drop synonym CDB_ADDM_SYSTEM_DIRECTIVES
/

drop synonym DBA_ADDM_TASK_DIRECTIVES
/

drop synonym USER_ADDM_TASK_DIRECTIVES
/

drop synonym CDB_ADDM_TASK_DIRECTIVES
/

drop synonym DBMS_CREDENTIAL
/

drop synonym DBA_CREDENTIALS
/

drop synonym CDB_CREDENTIALS
/

drop synonym USER_CREDENTIALS
/

drop synonym ALL_CREDENTIALS
/

drop synonym ALL_QUEUE_SCHEDULES
/

drop synonym DBA_QUEUE_SCHEDULES
/

drop synonym USER_QUEUE_SCHEDULES
/

drop synonym CDB_QUEUE_SCHEDULES
/

drop synonym DBA_XDS_ACL_REFRESH
/

drop synonym CDB_XDS_ACL_REFRESH
/

drop synonym ALL_XDS_ACL_REFRESH
/

drop synonym USER_XDS_ACL_REFRESH
/

drop synonym DBA_XDS_ACL_REFSTAT
/

drop synonym CDB_XDS_ACL_REFSTAT
/

drop synonym ALL_XDS_ACL_REFSTAT
/

drop synonym USER_XDS_ACL_REFSTAT
/

drop synonym DBA_XDS_LATEST_ACL_REFSTAT
/

drop synonym CDB_XDS_LATEST_ACL_REFSTAT
/

drop synonym ALL_XDS_LATEST_ACL_REFSTAT
/

drop synonym USER_XDS_LATEST_ACL_REFSTAT
/

drop synonym DBA_LOGMNR_PURGED_LOG
/

drop synonym CDB_LOGMNR_PURGED_LOG
/

drop synonym LOGMNR$ALWAYS_SUPLOG_COLUMNS
/

drop synonym LOGMNR$SCHEMA_ALLKEY_SUPLOG
/

drop synonym KUPCC
/

drop synonym LOGSTDBY_UNSUPPORTED_TABLES
/

drop synonym DBA_LOGSTDBY_UNSUPPORTED_TABLE
/

drop synonym CDB_LOGSTDBY_UNSUPPORTED_TABLE
/

drop synonym DBA_LOGSTDBY_UNSUPPORTED
/

drop synonym CDB_LOGSTDBY_UNSUPPORTED
/

drop synonym DBA_ROLLING_UNSUPPORTED
/

drop synonym CDB_ROLLING_UNSUPPORTED
/

drop synonym DBA_LOGSTDBY_NOT_UNIQUE
/

drop synonym CDB_LOGSTDBY_NOT_UNIQUE
/

drop synonym DBA_LOGSTDBY_PARAMETERS
/

drop synonym CDB_LOGSTDBY_PARAMETERS
/

drop synonym DBA_LOGSTDBY_PROGRESS
/

drop synonym CDB_LOGSTDBY_PROGRESS
/

drop synonym DBA_LOGSTDBY_LOG
/

drop synonym CDB_LOGSTDBY_LOG
/

drop synonym DBA_LOGSTDBY_SKIP_TRANSACTION
/

drop synonym CDB_LOGSTDBY_SKIP_TRANSACTION
/

drop synonym DBA_LOGSTDBY_SKIP
/

drop synonym CDB_LOGSTDBY_SKIP
/

drop synonym DBA_LOGSTDBY_EVENTS
/

drop synonym CDB_LOGSTDBY_EVENTS
/

drop synonym DBA_LOGSTDBY_HISTORY
/

drop synonym CDB_LOGSTDBY_HISTORY
/

drop synonym DBA_LOGSTDBY_EDS_TABLES
/

drop synonym CDB_LOGSTDBY_EDS_TABLES
/

drop synonym DBA_LOGSTDBY_EDS_SUPPORTED
/

drop synonym CDB_LOGSTDBY_EDS_SUPPORTED
/

drop synonym DBA_LOGSTDBY_PLSQL_MAP
/

drop synonym CDB_LOGSTDBY_PLSQL_MAP
/

drop synonym DBA_LOGSTDBY_PLSQL_SUPPORT
/

drop synonym CDB_LOGSTDBY_PLSQL_SUPPORT
/

drop synonym V$LOGSTDBY
/

drop synonym V$LOGSTDBY_STATS
/

drop synonym V$LOGSTDBY_TRANSACTION
/

drop synonym V$LOGSTDBY_PROGRESS
/

drop synonym V$LOGSTDBY_PROCESS
/

drop synonym V$LOGSTDBY_STATE
/

drop synonym GV$LOGSTDBY
/

drop synonym GV$LOGSTDBY_STATS
/

drop synonym GV$LOGSTDBY_TRANSACTION
/

drop synonym GV$LOGSTDBY_PROGRESS
/

drop synonym GV$LOGSTDBY_PROCESS
/

drop synonym GV$LOGSTDBY_STATE
/

drop synonym DBA_AUTO_INDEX_EXECUTIONS
/

drop synonym CDB_AUTO_INDEX_EXECUTIONS
/

drop synonym DBA_AUTO_INDEX_CONFIG
/

drop synonym CDB_AUTO_INDEX_CONFIG
/

drop synonym DBA_AUTO_INDEX_STATISTICS
/

drop synonym CDB_AUTO_INDEX_STATISTICS
/

drop synonym DBA_AUTO_INDEX_IND_ACTIONS
/

drop synonym CDB_AUTO_INDEX_IND_ACTIONS
/

drop synonym DBA_AUTO_INDEX_SQL_ACTIONS
/

drop synonym CDB_AUTO_INDEX_SQL_ACTIONS
/

drop synonym DBA_AUTO_INDEX_VERIFICATIONS
/

drop synonym CDB_AUTO_INDEX_VERIFICATIONS
/

drop synonym CDB_EXPORT_OBJECTS
/

drop synonym CDB_EXPORT_PATHS
/

drop synonym DBMS_DATA_MINING_TRANSFORM
/

drop synonym DBMS_DATA_MINING
/

drop synonym DBMS_PREDICTIVE_ANALYTICS
/

drop synonym DBMS_AUTO_TASK
/

drop synonym DBMS_AUTO_TASK_ADMIN
/

drop synonym DBMS_AUTO_TASK_IMMEDIATE
/

drop synonym DBMS_AUTO_TASK_EXPORT
/

drop synonym DBA_OUTSTANDING_ALERTS
/

drop synonym CDB_OUTSTANDING_ALERTS
/

drop synonym DBA_ALERT_HISTORY
/

drop synonym CDB_ALERT_HISTORY
/

drop synonym DBA_ALERT_HISTORY_DETAIL
/

drop synonym CDB_ALERT_HISTORY_DETAIL
/

drop synonym DBA_THRESHOLDS
/

drop synonym CDB_THRESHOLDS
/

drop synonym DBA_TABLESPACE_THRESHOLDS
/

drop synonym CDB_TABLESPACE_THRESHOLDS
/

drop synonym DBA_AUTOTASK_OPERATION
/

drop synonym CDB_AUTOTASK_OPERATION
/

drop synonym DBA_AUTOTASK_TASK
/

drop synonym CDB_AUTOTASK_TASK
/

drop synonym DBA_AUTOTASK_SCHEDULE
/

drop synonym CDB_AUTOTASK_SCHEDULE
/

drop synonym DBA_AUTOTASK_CLIENT_JOB
/

drop synonym CDB_AUTOTASK_CLIENT_JOB
/

drop synonym DBA_AUTOTASK_WINDOW_CLIENTS
/

drop synonym CDB_AUTOTASK_WINDOW_CLIENTS
/

drop synonym DBA_AUTOTASK_WINDOW_HISTORY
/

drop synonym CDB_AUTOTASK_WINDOW_HISTORY
/

drop synonym DBA_AUTOTASK_CLIENT_HISTORY
/

drop synonym CDB_AUTOTASK_CLIENT_HISTORY
/

drop synonym DBA_AUTOTASK_JOB_HISTORY
/

drop synonym CDB_AUTOTASK_JOB_HISTORY
/

drop synonym DBA_AUTOTASK_CLIENT
/

drop synonym CDB_AUTOTASK_CLIENT
/

drop synonym DBA_AUTOTASK_STATUS
/

drop synonym CDB_AUTOTASK_STATUS
/

drop synonym AWR_CDB_BASELINE
/

drop synonym AWR_ROOT_BASELINE
/

drop synonym AWR_PDB_BASELINE
/

drop synonym DBA_HIST_BASELINE
/

drop synonym CDB_HIST_BASELINE
/

drop synonym AWR_CDB_BASELINE_DETAILS
/

drop synonym AWR_ROOT_BASELINE_DETAILS
/

drop synonym AWR_PDB_BASELINE_DETAILS
/

drop synonym DBA_HIST_BASELINE_DETAILS
/

drop synonym CDB_HIST_BASELINE_DETAILS
/

drop synonym AWR_CDB_SQLBIND
/

drop synonym AWR_ROOT_SQLBIND
/

drop synonym AWR_PDB_SQLBIND
/

drop synonym DBA_HIST_SQLBIND
/

drop synonym CDB_HIST_SQLBIND
/

drop synonym DBA_SQLTUNE_BINDS
/

drop synonym CDB_SQLTUNE_BINDS
/

drop synonym DBA_SQLTUNE_STATISTICS
/

drop synonym CDB_SQLTUNE_STATISTICS
/

drop synonym DBA_SQLTUNE_PLANS
/

drop synonym CDB_SQLTUNE_PLANS
/

drop synonym DBA_SQLTUNE_RATIONALE_PLAN
/

drop synonym CDB_SQLTUNE_RATIONALE_PLAN
/

drop synonym USER_SQLTUNE_BINDS
/

drop synonym USER_SQLTUNE_STATISTICS
/

drop synonym USER_SQLTUNE_PLANS
/

drop synonym USER_SQLTUNE_RATIONALE_PLAN
/

drop synonym DBA_SQLSET
/

drop synonym DBA_SQLSET_DEFINITIONS
/

drop synonym CDB_SQLSET
/

drop synonym DBA_SQLSET_REFERENCES
/

drop synonym CDB_SQLSET_REFERENCES
/

drop synonym DBA_SQLSET_STATEMENTS
/

drop synonym CDB_SQLSET_STATEMENTS
/

drop synonym DBA_SQLSET_BINDS
/

drop synonym CDB_SQLSET_BINDS
/

drop synonym DBA_SQLSET_PLANS
/

drop synonym CDB_SQLSET_PLANS
/

drop synonym USER_SQLSET
/

drop synonym USER_SQLSET_DEFINITIONS
/

drop synonym USER_SQLSET_STATEMENTS
/

drop synonym USER_SQLSET_REFERENCES
/

drop synonym USER_SQLSET_BINDS
/

drop synonym USER_SQLSET_PLANS
/

drop synonym ALL_SQLSET
/

drop synonym ALL_SQLSET_STATEMENTS
/

drop synonym ALL_SQLSET_REFERENCES
/

drop synonym ALL_SQLSET_PLANS
/

drop synonym ALL_SQLSET_BINDS
/

drop synonym "_ALL_SQLSET_STATEMENTS_ONLY"
/

drop synonym "_ALL_SQLSET_STATISTICS_ONLY"
/

drop synonym "_ALL_SQLSET_STATEMENTS_PHV"
/

drop synonym "_ALL_SQLSET_STS_TOPACK"
/

drop synonym DBMSHSXP_SQL_PROFILE_ATTR
/

drop synonym DBMSHSXP
/

drop synonym DBA_SQL_MONITOR_USAGE
/

drop synonym CDB_SQL_MONITOR_USAGE
/

drop synonym DBA_INDEX_USAGE
/

drop synonym CDB_INDEX_USAGE
/

drop synonym DBA_ADVISOR_SQLA_WK_MAP
/

drop synonym USER_ADVISOR_SQLA_WK_MAP
/

drop synonym CDB_ADVISOR_SQLA_WK_MAP
/

drop synonym DBA_ADVISOR_SQLA_WK_SUM
/

drop synonym USER_ADVISOR_SQLA_WK_SUM
/

drop synonym CDB_ADVISOR_SQLA_WK_SUM
/

drop synonym DBA_ADVISOR_SQLA_WK_STMTS
/

drop synonym USER_ADVISOR_SQLA_WK_STMTS
/

drop synonym CDB_ADVISOR_SQLA_WK_STMTS
/

drop synonym DBA_ADVISOR_SQLA_TABLES
/

drop synonym USER_ADVISOR_SQLA_TABLES
/

drop synonym CDB_ADVISOR_SQLA_TABLES
/

drop synonym DBA_ADVISOR_SQLA_TABVOL
/

drop synonym USER_ADVISOR_SQLA_TABVOL
/

drop synonym CDB_ADVISOR_SQLA_TABVOL
/

drop synonym DBA_ADVISOR_SQLA_COLVOL
/

drop synonym USER_ADVISOR_SQLA_COLVOL
/

drop synonym CDB_ADVISOR_SQLA_COLVOL
/

drop synonym DBA_ADVISOR_SQLA_REC_SUM
/

drop synonym USER_ADVISOR_SQLA_REC_SUM
/

drop synonym CDB_ADVISOR_SQLA_REC_SUM
/

drop synonym DBA_ADVISOR_SQLW_SUM
/

drop synonym USER_ADVISOR_SQLW_SUM
/

drop synonym CDB_ADVISOR_SQLW_SUM
/

drop synonym DBA_ADVISOR_SQLW_TEMPLATES
/

drop synonym USER_ADVISOR_SQLW_TEMPLATES
/

drop synonym CDB_ADVISOR_SQLW_TEMPLATES
/

drop synonym DBA_ADVISOR_SQLW_STMTS
/

drop synonym USER_ADVISOR_SQLW_STMTS
/

drop synonym CDB_ADVISOR_SQLW_STMTS
/

drop synonym DBA_ADVISOR_SQLW_TABLES
/

drop synonym USER_ADVISOR_SQLW_TABLES
/

drop synonym CDB_ADVISOR_SQLW_TABLES
/

drop synonym DBA_ADVISOR_SQLW_TABVOL
/

drop synonym USER_ADVISOR_SQLW_TABVOL
/

drop synonym CDB_ADVISOR_SQLW_TABVOL
/

drop synonym DBA_ADVISOR_SQLW_COLVOL
/

drop synonym USER_ADVISOR_SQLW_COLVOL
/

drop synonym CDB_ADVISOR_SQLW_COLVOL
/

drop synonym DBA_ADVISOR_SQLW_PARAMETERS
/

drop synonym USER_ADVISOR_SQLW_PARAMETERS
/

drop synonym CDB_ADVISOR_SQLW_PARAMETERS
/

drop synonym DBA_ADVISOR_SQLW_JOURNAL
/

drop synonym USER_ADVISOR_SQLW_JOURNAL
/

drop synonym CDB_ADVISOR_SQLW_JOURNAL
/

drop synonym DBA_TUNE_MVIEW
/

drop synonym CDB_TUNE_MVIEW
/

drop synonym USER_TUNE_MVIEW
/

drop synonym DBA_FLASHBACK_ARCHIVE
/

drop synonym CDB_FLASHBACK_ARCHIVE
/

drop synonym USER_FLASHBACK_ARCHIVE
/

drop synonym DBA_FLASHBACK_ARCHIVE_TS
/

drop synonym CDB_FLASHBACK_ARCHIVE_TS
/

drop synonym DBA_FLASHBACK_ARCHIVE_TABLES
/

drop synonym CDB_FLASHBACK_ARCHIVE_TABLES
/

drop synonym USER_FLASHBACK_ARCHIVE_TABLES
/

drop synonym DBA_CAPTURE
/

drop synonym CDB_CAPTURE
/

drop synonym DBA_STREAMS_SPLIT_MERGE
/

drop synonym CDB_STREAMS_SPLIT_MERGE
/

drop synonym DBA_STREAMS_SPLIT_MERGE_HIST
/

drop synonym CDB_STREAMS_SPLIT_MERGE_HIST
/

drop synonym DBA_XSTREAM_SPLIT_MERGE
/

drop synonym CDB_XSTREAM_SPLIT_MERGE
/

drop synonym DBA_XSTREAM_SPLIT_MERGE_HIST
/

drop synonym CDB_XSTREAM_SPLIT_MERGE_HIST
/

drop synonym ALL_CAPTURE
/

drop synonym DBA_CAPTURE_PARAMETERS
/

drop synonym CDB_CAPTURE_PARAMETERS
/

drop synonym ALL_CAPTURE_PARAMETERS
/

drop synonym DBA_CAPTURE_PREPARED_DATABASE
/

drop synonym CDB_CAPTURE_PREPARED_DATABASE
/

drop synonym ALL_CAPTURE_PREPARED_DATABASE
/

drop synonym DBA_CAPTURE_PREPARED_SCHEMAS
/

drop synonym CDB_CAPTURE_PREPARED_SCHEMAS
/

drop synonym ALL_CAPTURE_PREPARED_SCHEMAS
/

drop synonym DBA_CAPTURE_PREPARED_TABLES
/

drop synonym CDB_CAPTURE_PREPARED_TABLES
/

drop synonym ALL_CAPTURE_PREPARED_TABLES
/

drop synonym DBA_SYNC_CAPTURE_PREPARED_TABS
/

drop synonym CDB_SYNC_CAPTURE_PREPARED_TABS
/

drop synonym ALL_SYNC_CAPTURE_PREPARED_TABS
/

drop synonym DBA_CAPTURE_EXTRA_ATTRIBUTES
/

drop synonym CDB_CAPTURE_EXTRA_ATTRIBUTES
/

drop synonym ALL_CAPTURE_EXTRA_ATTRIBUTES
/

drop synonym DBA_REGISTERED_ARCHIVED_LOG
/

drop synonym CDB_REGISTERED_ARCHIVED_LOG
/

drop synonym GV$STREAMS_CAPTURE
/

drop synonym V$STREAMS_CAPTURE
/

drop synonym GV$XSTREAM_CAPTURE
/

drop synonym V$XSTREAM_CAPTURE
/

drop synonym GV$GOLDENGATE_CAPTURE
/

drop synonym V$GOLDENGATE_CAPTURE
/

drop synonym "_V$SXGG_CAPTURE"
/

drop synonym "_GV$SXGG_CAPTURE"
/

drop synonym DBA_SYNC_CAPTURE
/

drop synonym CDB_SYNC_CAPTURE
/

drop synonym ALL_SYNC_CAPTURE
/

drop synonym DBA_GG_SUPPORTED_PACKAGES
/

drop synonym CDB_GG_SUPPORTED_PACKAGES
/

drop synonym DBA_GG_PROCEDURE_ANNOTATION
/

drop synonym CDB_GG_PROCEDURE_ANNOTATION
/

drop synonym DBA_GG_PROC_OBJECT_EXCLUSION
/

drop synonym CDB_GG_PROC_OBJECT_EXCLUSION
/

drop synonym DBA_GG_SUPPORTED_PROCEDURES
/

drop synonym CDB_GG_SUPPORTED_PROCEDURES
/

drop synonym DBA_APPLY
/

drop synonym CDB_APPLY
/

drop synonym ALL_APPLY
/

drop synonym DBA_APPLY_PARAMETERS
/

drop synonym CDB_APPLY_PARAMETERS
/

drop synonym ALL_APPLY_PARAMETERS
/

drop synonym DBA_APPLY_INSTANTIATED_OBJECTS
/

drop synonym CDB_APPLY_INSTANTIATED_OBJECTS
/

drop synonym ALL_APPLY_INSTANTIATED_OBJECTS
/

drop synonym "_DBA_APPLY_INST_OBJECTS"
/

drop synonym DBA_APPLY_INSTANTIATED_SCHEMAS
/

drop synonym CDB_APPLY_INSTANTIATED_SCHEMAS
/

drop synonym ALL_APPLY_INSTANTIATED_SCHEMAS
/

drop synonym "_DBA_APPLY_INST_SCHEMAS"
/

drop synonym DBA_APPLY_INSTANTIATED_GLOBAL
/

drop synonym CDB_APPLY_INSTANTIATED_GLOBAL
/

drop synonym ALL_APPLY_INSTANTIATED_GLOBAL
/

drop synonym "_DBA_APPLY_INST_GLOBAL"
/

drop synonym DBA_APPLY_VALUE_DEPENDENCIES
/

drop synonym DBA_APPLY_OBJECT_DEPENDENCIES
/

drop synonym DBA_APPLY_KEY_COLUMNS
/

drop synonym CDB_APPLY_KEY_COLUMNS
/

drop synonym ALL_APPLY_KEY_COLUMNS
/

drop synonym DBA_APPLY_CONFLICT_COLUMNS
/

drop synonym CDB_APPLY_CONFLICT_COLUMNS
/

drop synonym ALL_APPLY_CONFLICT_COLUMNS
/

drop synonym DBA_APPLY_TABLE_COLUMNS
/

drop synonym CDB_APPLY_TABLE_COLUMNS
/

drop synonym ALL_APPLY_TABLE_COLUMNS
/

drop synonym DBA_APPLY_DML_HANDLERS
/

drop synonym CDB_APPLY_DML_HANDLERS
/

drop synonym ALL_APPLY_DML_HANDLERS
/

drop synonym DBA_APPLY_PROGRESS
/

drop synonym CDB_APPLY_PROGRESS
/

drop synonym ALL_APPLY_PROGRESS
/

drop synonym DBA_APPLY_ERROR
/

drop synonym CDB_APPLY_ERROR
/

drop synonym ALL_APPLY_ERROR
/

drop synonym USER_APPLY_ERROR
/

drop synonym DBA_APPLY_ERROR_MESSAGES
/

drop synonym CDB_APPLY_ERROR_MESSAGES
/

drop synonym ALL_APPLY_ERROR_MESSAGES
/

drop synonym DBA_APPLY_ENQUEUE
/

drop synonym CDB_APPLY_ENQUEUE
/

drop synonym ALL_APPLY_ENQUEUE
/

drop synonym DBA_APPLY_EXECUTE
/

drop synonym CDB_APPLY_EXECUTE
/

drop synonym ALL_APPLY_EXECUTE
/

drop synonym DBA_APPLY_SPILL_TXN
/

drop synonym CDB_APPLY_SPILL_TXN
/

drop synonym ALL_APPLY_SPILL_TXN
/

drop synonym GV$STREAMS_APPLY_COORDINATOR
/

drop synonym V$STREAMS_APPLY_COORDINATOR
/

drop synonym "_V$SXGG_APPLY_COORDINATOR"
/

drop synonym "_GV$SXGG_APPLY_COORDINATOR"
/

drop synonym GV$STREAMS_APPLY_SERVER
/

drop synonym V$STREAMS_APPLY_SERVER
/

drop synonym "_V$SXGG_APPLY_SERVER"
/

drop synonym "_GV$SXGG_APPLY_SERVER"
/

drop synonym GV$STREAMS_APPLY_READER
/

drop synonym V$STREAMS_APPLY_READER
/

drop synonym "_V$SXGG_APPLY_READER"
/

drop synonym "_GV$SXGG_APPLY_READER"
/

drop synonym GV$XSTREAM_APPLY_COORDINATOR
/

drop synonym V$XSTREAM_APPLY_COORDINATOR
/

drop synonym GV$XSTREAM_APPLY_SERVER
/

drop synonym V$XSTREAM_APPLY_SERVER
/

drop synonym GV$XSTREAM_APPLY_READER
/

drop synonym V$XSTREAM_APPLY_READER
/

drop synonym GV$GG_APPLY_COORDINATOR
/

drop synonym V$GG_APPLY_COORDINATOR
/

drop synonym GV$GG_APPLY_SERVER
/

drop synonym V$GG_APPLY_SERVER
/

drop synonym GV$GG_APPLY_READER
/

drop synonym V$GG_APPLY_READER
/

drop synonym GV$XSTREAM_OUTBOUND_SERVER
/

drop synonym V$XSTREAM_OUTBOUND_SERVER
/

drop synonym GV$XSTREAM_TABLE_STATS
/

drop synonym V$XSTREAM_TABLE_STATS
/

drop synonym GV$GOLDENGATE_TABLE_STATS
/

drop synonym V$GOLDENGATE_TABLE_STATS
/

drop synonym GV$GOLDENGATE_PROCEDURE_STATS
/

drop synonym V$GOLDENGATE_PROCEDURE_STATS
/

drop synonym GV$GG_APPLY_RECEIVER
/

drop synonym V$GG_APPLY_RECEIVER
/

drop synonym GV$XSTREAM_APPLY_RECEIVER
/

drop synonym V$XSTREAM_APPLY_RECEIVER
/

drop synonym "_DBA_GGXSTREAM_OUTBOUND"
/

drop synonym DBA_XSTREAM_OUTBOUND
/

drop synonym CDB_XSTREAM_OUTBOUND
/

drop synonym ALL_XSTREAM_OUTBOUND
/

drop synonym DBA_XSTREAM_OUTBOUND_PROGRESS
/

drop synonym CDB_XSTREAM_OUTBOUND_PROGRESS
/

drop synonym ALL_XSTREAM_OUTBOUND_PROGRESS
/

drop synonym "_DBA_GGXSTREAM_INBOUND"
/

drop synonym DBA_XSTREAM_INBOUND
/

drop synonym CDB_XSTREAM_INBOUND
/

drop synonym ALL_XSTREAM_INBOUND
/

drop synonym DBA_XSTREAM_INBOUND_PROGRESS
/

drop synonym CDB_XSTREAM_INBOUND_PROGRESS
/

drop synonym ALL_XSTREAM_INBOUND_PROGRESS
/

drop synonym DBA_GOLDENGATE_INBOUND
/

drop synonym CDB_GOLDENGATE_INBOUND
/

drop synonym ALL_GOLDENGATE_INBOUND
/

drop synonym DBA_GG_INBOUND_PROGRESS
/

drop synonym CDB_GG_INBOUND_PROGRESS
/

drop synonym ALL_GG_INBOUND_PROGRESS
/

drop synonym DBA_STREAMS_STMT_HANDLERS
/

drop synonym CDB_STREAMS_STMT_HANDLERS
/

drop synonym DBA_XSTREAM_STMT_HANDLERS
/

drop synonym CDB_XSTREAM_STMT_HANDLERS
/

drop synonym DBA_STREAMS_STMTS
/

drop synonym CDB_STREAMS_STMTS
/

drop synonym DBA_XSTREAM_STMTS
/

drop synonym CDB_XSTREAM_STMTS
/

drop synonym DBA_APPLY_CHANGE_HANDLERS
/

drop synonym CDB_APPLY_CHANGE_HANDLERS
/

drop synonym ALL_APPLY_CHANGE_HANDLERS
/

drop synonym DBA_APPLY_DML_CONF_HANDLERS
/

drop synonym CDB_APPLY_DML_CONF_HANDLERS
/

drop synonym ALL_APPLY_DML_CONF_HANDLERS
/

drop synonym DBA_APPLY_DML_CONF_COLUMNS
/

drop synonym CDB_APPLY_DML_CONF_COLUMNS
/

drop synonym ALL_APPLY_DML_CONF_COLUMNS
/

drop synonym DBA_APPLY_HANDLE_COLLISIONS
/

drop synonym CDB_APPLY_HANDLE_COLLISIONS
/

drop synonym ALL_APPLY_HANDLE_COLLISIONS
/

drop synonym DBA_APPLY_REPERROR_HANDLERS
/

drop synonym CDB_APPLY_REPERROR_HANDLERS
/

drop synonym ALL_APPLY_REPERROR_HANDLERS
/

drop synonym DBA_GG_AUTO_CDR_TABLES
/

drop synonym CDB_GG_AUTO_CDR_TABLES
/

drop synonym ALL_GG_AUTO_CDR_TABLES
/

drop synonym DBA_GG_AUTO_CDR_COLUMNS
/

drop synonym CDB_GG_AUTO_CDR_COLUMNS
/

drop synonym ALL_GG_AUTO_CDR_COLUMNS
/

drop synonym DBA_GG_AUTO_CDR_COLUMN_GROUPS
/

drop synonym CDB_GG_AUTO_CDR_COLUMN_GROUPS
/

drop synonym ALL_GG_AUTO_CDR_COLUMN_GROUPS
/

drop synonym DBA_PROPAGATION
/

drop synonym CDB_PROPAGATION
/

drop synonym ALL_PROPAGATION
/

drop synonym DBA_FILE_GROUPS
/

drop synonym CDB_FILE_GROUPS
/

drop synonym DBA_FILE_GROUP_VERSIONS
/

drop synonym CDB_FILE_GROUP_VERSIONS
/

drop synonym DBA_FILE_GROUP_EXPORT_INFO
/

drop synonym CDB_FILE_GROUP_EXPORT_INFO
/

drop synonym DBA_FILE_GROUP_FILES
/

drop synonym CDB_FILE_GROUP_FILES
/

drop synonym DBA_FILE_GROUP_TABLESPACES
/

drop synonym CDB_FILE_GROUP_TABLESPACES
/

drop synonym DBA_FILE_GROUP_TABLES
/

drop synonym CDB_FILE_GROUP_TABLES
/

drop synonym ALL_FILE_GROUPS
/

drop synonym ALL_FILE_GROUP_VERSIONS
/

drop synonym ALL_FILE_GROUP_EXPORT_INFO
/

drop synonym ALL_FILE_GROUP_FILES
/

drop synonym ALL_FILE_GROUP_TABLESPACES
/

drop synonym ALL_FILE_GROUP_TABLES
/

drop synonym USER_FILE_GROUPS
/

drop synonym USER_FILE_GROUP_VERSIONS
/

drop synonym USER_FILE_GROUP_EXPORT_INFO
/

drop synonym USER_FILE_GROUP_FILES
/

drop synonym USER_FILE_GROUP_TABLESPACES
/

drop synonym USER_FILE_GROUP_TABLES
/

drop synonym "_DBA_STREAMS_COMPONENT"
/

drop synonym "_DBA_STREAMS_COMPONENT_LINK"
/

drop synonym "_DBA_STREAMS_COMPONENT_PROP"
/

drop synonym "_DBA_STREAMS_COMPONENT_STAT"
/

drop synonym "_DBA_STREAMS_COMPONENT_EVENT"
/

drop synonym "_DBA_STREAMS_FINDINGS"
/

drop synonym "_DBA_STREAMS_RECOMMENDATIONS"
/

drop synonym "_DBA_STREAMS_ACTIONS"
/

drop synonym DBA_STREAMS_TP_DATABASE
/

drop synonym CDB_STREAMS_TP_DATABASE
/

drop synonym DBA_STREAMS_TP_COMPONENT
/

drop synonym CDB_STREAMS_TP_COMPONENT
/

drop synonym DBA_STREAMS_TP_COMPONENT_LINK
/

drop synonym CDB_STREAMS_TP_COMPONENT_LINK
/

drop synonym "_DBA_STREAMS_TP_COMPONENT_PROP"
/

drop synonym DBA_STREAMS_TP_COMPONENT_STAT
/

drop synonym CDB_STREAMS_TP_COMPONENT_STAT
/

drop synonym DBA_STREAMS_TP_PATH_STAT
/

drop synonym CDB_STREAMS_TP_PATH_STAT
/

drop synonym DBA_STREAMS_TP_PATH_BOTTLENECK
/

drop synonym CDB_STREAMS_TP_PATH_BOTTLENECK
/

drop synonym DBA_STREAMS_MESSAGE_CONSUMERS
/

drop synonym CDB_STREAMS_MESSAGE_CONSUMERS
/

drop synonym ALL_STREAMS_MESSAGE_CONSUMERS
/

drop synonym DBA_STREAMS_GLOBAL_RULES
/

drop synonym CDB_STREAMS_GLOBAL_RULES
/

drop synonym ALL_STREAMS_GLOBAL_RULES
/

drop synonym DBA_STREAMS_SCHEMA_RULES
/

drop synonym CDB_STREAMS_SCHEMA_RULES
/

drop synonym ALL_STREAMS_SCHEMA_RULES
/

drop synonym DBA_STREAMS_TABLE_RULES
/

drop synonym CDB_STREAMS_TABLE_RULES
/

drop synonym ALL_STREAMS_TABLE_RULES
/

drop synonym DBA_STREAMS_MESSAGE_RULES
/

drop synonym CDB_STREAMS_MESSAGE_RULES
/

drop synonym ALL_STREAMS_MESSAGE_RULES
/

drop synonym DBA_STREAMS_RULES
/

drop synonym CDB_STREAMS_RULES
/

drop synonym ALL_STREAMS_RULES
/

drop synonym DBA_SYNC_CAPTURE_TABLES
/

drop synonym CDB_SYNC_CAPTURE_TABLES
/

drop synonym ALL_SYNC_CAPTURE_TABLES
/

drop synonym DBA_XSTREAM_RULES
/

drop synonym CDB_XSTREAM_RULES
/

drop synonym ALL_XSTREAM_RULES
/

drop synonym DBA_GOLDENGATE_RULES
/

drop synonym CDB_GOLDENGATE_RULES
/

drop synonym ALL_GOLDENGATE_RULES
/

drop synonym DBA_GOLDENGATE_CONTAINER_RULES
/

drop synonym CDB_GOLDENGATE_CONTAINER_RULES
/

drop synonym ALL_GOLDENGATE_CONTAINER_RULES
/

drop synonym DBA_REPL_DBNAME_MAPPING
/

drop synonym CDB_REPL_DBNAME_MAPPING
/

drop synonym ALL_REPL_DBNAME_MAPPING
/

drop synonym DBA_STREAMS_TRANSFORM_FUNCTION
/

drop synonym CDB_STREAMS_TRANSFORM_FUNCTION
/

drop synonym ALL_STREAMS_TRANSFORM_FUNCTION
/

drop synonym DBA_STREAMS_ADMINISTRATOR
/

drop synonym CDB_STREAMS_ADMINISTRATOR
/

drop synonym DBA_XSTREAM_ADMINISTRATOR
/

drop synonym CDB_XSTREAM_ADMINISTRATOR
/

drop synonym ALL_XSTREAM_ADMINISTRATOR
/

drop synonym DBA_STREAMS_TRANSFORMATIONS
/

drop synonym CDB_STREAMS_TRANSFORMATIONS
/

drop synonym DBA_XSTREAM_TRANSFORMATIONS
/

drop synonym CDB_XSTREAM_TRANSFORMATIONS
/

drop synonym ALL_STREAMS_TRANSFORMATIONS
/

drop synonym ALL_XSTREAM_TRANSFORMATIONS
/

drop synonym DBA_STREAMS_RENAME_SCHEMA
/

drop synonym CDB_STREAMS_RENAME_SCHEMA
/

drop synonym DBA_STREAMS_RENAME_TABLE
/

drop synonym CDB_STREAMS_RENAME_TABLE
/

drop synonym DBA_STREAMS_DELETE_COLUMN
/

drop synonym CDB_STREAMS_DELETE_COLUMN
/

drop synonym DBA_STREAMS_KEEP_COLUMNS
/

drop synonym CDB_STREAMS_KEEP_COLUMNS
/

drop synonym ALL_STREAMS_KEEP_COLUMNS
/

drop synonym DBA_STREAMS_RENAME_COLUMN
/

drop synonym CDB_STREAMS_RENAME_COLUMN
/

drop synonym DBA_STREAMS_ADD_COLUMN
/

drop synonym CDB_STREAMS_ADD_COLUMN
/

drop synonym DBA_RECOVERABLE_SCRIPT
/

drop synonym CDB_RECOVERABLE_SCRIPT
/

drop synonym DBA_RECOVERABLE_SCRIPT_HIST
/

drop synonym CDB_RECOVERABLE_SCRIPT_HIST
/

drop synonym DBA_RECOVERABLE_SCRIPT_PARAMS
/

drop synonym CDB_RECOVERABLE_SCRIPT_PARAMS
/

drop synonym DBA_RECOVERABLE_SCRIPT_BLOCKS
/

drop synonym CDB_RECOVERABLE_SCRIPT_BLOCKS
/

drop synonym DBA_RECOVERABLE_SCRIPT_ERRORS
/

drop synonym CDB_RECOVERABLE_SCRIPT_ERRORS
/

drop synonym GV$STREAMS_TRANSACTION
/

drop synonym V$STREAMS_TRANSACTION
/

drop synonym GV$XSTREAM_TRANSACTION
/

drop synonym V$XSTREAM_TRANSACTION
/

drop synonym GV$GOLDENGATE_TRANSACTION
/

drop synonym V$GOLDENGATE_TRANSACTION
/

drop synonym "_V$SXGG_TRANSACTION"
/

drop synonym "_GV$SXGG_TRANSACTION"
/

drop synonym GV$STREAMS_MESSAGE_TRACKING
/

drop synonym V$STREAMS_MESSAGE_TRACKING
/

drop synonym GV$XSTREAM_MESSAGE_TRACKING
/

drop synonym V$XSTREAM_MESSAGE_TRACKING
/

drop synonym GV$GOLDENGATE_MESSAGE_TRACKING
/

drop synonym V$GOLDENGATE_MESSAGE_TRACKING
/

drop synonym "_V$SXGG_MESSAGE_TRACKING"
/

drop synonym "_GV$SXGG_MESSAGE_TRACKING"
/

drop synonym GV$STREAMS_POOL_STATISTICS
/

drop synonym V$STREAMS_POOL_STATISTICS
/

drop synonym DBA_GOLDENGATE_PRIVILEGES
/

drop synonym CDB_GOLDENGATE_PRIVILEGES
/

drop synonym ALL_GOLDENGATE_PRIVILEGES
/

drop synonym USER_GOLDENGATE_PRIVILEGES
/

drop synonym DBA_COMPARISON
/

drop synonym CDB_COMPARISON
/

drop synonym USER_COMPARISON
/

drop synonym DBA_COMPARISON_COLUMNS
/

drop synonym CDB_COMPARISON_COLUMNS
/

drop synonym USER_COMPARISON_COLUMNS
/

drop synonym DBA_COMPARISON_SCAN
/

drop synonym CDB_COMPARISON_SCAN
/

drop synonym DBA_COMPARISON_SCAN_SUMMARY
/

drop synonym CDB_COMPARISON_SCAN_SUMMARY
/

drop synonym ALL_COMPARISON_SCAN_SUMMARY
/

drop synonym USER_COMPARISON_SCAN
/

drop synonym USER_COMPARISON_SCAN_SUMMARY
/

drop synonym DBA_COMPARISON_SCAN_VALUES
/

drop synonym CDB_COMPARISON_SCAN_VALUES
/

drop synonym USER_COMPARISON_SCAN_VALUES
/

drop synonym DBA_COMPARISON_ROW_DIF
/

drop synonym CDB_COMPARISON_ROW_DIF
/

drop synonym USER_COMPARISON_ROW_DIF
/

drop synonym "_USER_COMPARISON_ROW_DIF"
/

drop synonym DBA_STREAMS_COLUMNS
/

drop synonym CDB_STREAMS_COLUMNS
/

drop synonym ALL_STREAMS_COLUMNS
/

drop synonym DBA_STREAMS_UNSUPPORTED
/

drop synonym CDB_STREAMS_UNSUPPORTED
/

drop synonym ALL_STREAMS_UNSUPPORTED
/

drop synonym DBA_STREAMS_NEWLY_SUPPORTED
/

drop synonym CDB_STREAMS_NEWLY_SUPPORTED
/

drop synonym ALL_STREAMS_NEWLY_SUPPORTED
/

drop synonym DBA_XSTREAM_OUT_SUPPORT_MODE
/

drop synonym CDB_XSTREAM_OUT_SUPPORT_MODE
/

drop synonym ALL_XSTREAM_OUT_SUPPORT_MODE
/

drop synonym DBA_GOLDENGATE_SUPPORT_MODE
/

drop synonym CDB_GOLDENGATE_SUPPORT_MODE
/

drop synonym DBA_GOLDENGATE_NOT_UNIQUE
/

drop synonym CDB_GOLDENGATE_NOT_UNIQUE
/

drop synonym DBA_REPLICATION_PROCESS_EVENTS
/

drop synonym ALL_REPLICATION_PROCESS_EVENTS
/

drop synonym CDB_REPLICATION_PROCESS_EVENTS
/

drop synonym USER_PARALLEL_EXECUTE_TASKS
/

drop synonym USER_PARALLEL_EXECUTE_CHUNKS
/

drop synonym DBA_PARALLEL_EXECUTE_TASKS
/

drop synonym CDB_PARALLEL_EXECUTE_TASKS
/

drop synonym DBA_PARALLEL_EXECUTE_CHUNKS
/

drop synonym CDB_PARALLEL_EXECUTE_CHUNKS
/

drop synonym DBFS_CONTENT
/

drop synonym DBFS_CONTENT_PROPERTIES
/

drop synonym USER_DBFS_HS_FILES
/

drop synonym CDB_WORKLOAD_FILTERS
/

drop synonym DBA_WORKLOAD_FILTERS
/

drop synonym CDB_WORKLOAD_REPLAY_FILTER_SET
/

drop synonym DBA_WORKLOAD_CAPTURES
/

drop synonym CDB_WORKLOAD_CAPTURES
/

drop synonym DBA_WORKLOAD_CAPTURE_SQLTEXT
/

drop synonym DBA_WORKLOAD_LONG_SQLTEXT
/

drop synonym DBA_RAT_CAPTURE_SCHEMA_INFO
/

drop synonym DBA_WORKLOAD_REPLAYS
/

drop synonym CDB_WORKLOAD_REPLAYS
/

drop synonym DBA_WORKLOAD_DIV_SUMMARY
/

drop synonym CDB_WORKLOAD_DIV_SUMMARY
/

drop synonym DBA_WORKLOAD_REPLAY_DIVERGENCE
/

drop synonym CDB_WORKLOAD_REPLAY_DIVERGENCE
/

drop synonym DBA_WORKLOAD_CONNECTION_MAP
/

drop synonym CDB_WORKLOAD_CONNECTION_MAP
/

drop synonym CDB_WORKLOAD_USER_MAP
/

drop synonym DBA_WORKLOAD_USER_MAP
/

drop synonym DBA_WORKLOAD_ACTIVE_USER_MAP
/

drop synonym CDB_WORKLOAD_ACTIVE_USER_MAP
/

drop synonym DBA_WORKLOAD_REPLAY_FILTER_SET
/

drop synonym DBA_WORKLOAD_REPLAY_SCHEDULES
/

drop synonym CDB_WORKLOAD_REPLAY_SCHEDULES
/

drop synonym DBA_WORKLOAD_SCHEDULE_CAPTURES
/

drop synonym CDB_WORKLOAD_SCHEDULE_CAPTURES
/

drop synonym DBA_WORKLOAD_SCHEDULE_ORDERING
/

drop synonym CDB_WORKLOAD_SCHEDULE_ORDERING
/

drop synonym DBA_WORKLOAD_GROUP_ASSIGNMENTS
/

drop synonym CDB_WORKLOAD_GROUP_ASSIGNMENTS
/

drop synonym DBA_WORKLOAD_REPLAY_CLIENTS
/

drop synonym CDB_WORKLOAD_REPLAY_CLIENTS
/

drop synonym DBA_WORKLOAD_TRACKED_COMMITS
/

drop synonym CDB_WORKLOAD_TRACKED_COMMITS
/

drop synonym DBA_WORKLOAD_REPLAY_THREAD
/

drop synonym CDB_WORKLOAD_REPLAY_THREAD
/

drop synonym DBA_WORKLOAD_SQL_MAP
/

drop synonym CDB_WORKLOAD_SQL_MAP
/

drop synonym DBA_WI_JOBS
/

drop synonym CDB_WI_JOBS
/

drop synonym DBA_WI_TEMPLATES
/

drop synonym CDB_WI_TEMPLATES
/

drop synonym DBA_WI_STATEMENTS
/

drop synonym CDB_WI_STATEMENTS
/

drop synonym DBA_WI_OBJECTS
/

drop synonym CDB_WI_OBJECTS
/

drop synonym DBA_WI_CAPTURE_FILES
/

drop synonym CDB_WI_CAPTURE_FILES
/

drop synonym DBA_WI_TEMPLATE_EXECUTIONS
/

drop synonym CDB_WI_TEMPLATE_EXECUTIONS
/

drop synonym DBA_WI_PATTERNS
/

drop synonym CDB_WI_PATTERNS
/

drop synonym DBA_WI_PATTERN_ITEMS
/

drop synonym CDB_WI_PATTERN_ITEMS
/

drop synonym DBMS_DEBUG_JDWP_CUSTOM
/

drop synonym DBMS_JAVA_DUMP
/

drop synonym DBMS_LDAP
/

drop synonym DBMS_LDAP_UTL
/

drop synonym DBA_HEAT_MAP_SEG_HISTOGRAM
/

drop synonym CDB_HEAT_MAP_SEG_HISTOGRAM
/

drop synonym USER_HEAT_MAP_SEG_HISTOGRAM
/

drop synonym ALL_HEAT_MAP_SEG_HISTOGRAM
/

drop synonym DBA_HEAT_MAP_SEGMENT
/

drop synonym CDB_HEAT_MAP_SEGMENT
/

drop synonym USER_HEAT_MAP_SEGMENT
/

drop synonym ALL_HEAT_MAP_SEGMENT
/

drop synonym USER_ILMPOLICIES
/

drop synonym USER_ILMDATAMOVEMENTPOLICIES
/

drop synonym USER_ILMOBJECTS
/

drop synonym USER_ILMTASKS
/

drop synonym USER_ILMEVALUATIONDETAILS
/

drop synonym USER_ILMRESULTS
/

drop synonym DBA_ILMPOLICIES
/

drop synonym CDB_ILMPOLICIES
/

drop synonym DBA_ILMDATAMOVEMENTPOLICIES
/

drop synonym CDB_ILMDATAMOVEMENTPOLICIES
/

drop synonym DBA_ILMOBJECTS
/

drop synonym CDB_ILMOBJECTS
/

drop synonym DBA_ILMTASKS
/

drop synonym CDB_ILMTASKS
/

drop synonym DBA_ILMEVALUATIONDETAILS
/

drop synonym CDB_ILMEVALUATIONDETAILS
/

drop synonym DBA_ILMRESULTS
/

drop synonym CDB_ILMRESULTS
/

drop synonym DBA_ILMPARAMETERS
/

drop synonym CDB_ILMPARAMETERS
/

drop synonym DBA_COL_USAGE_STATISTICS
/

drop synonym CDB_COL_USAGE_STATISTICS
/

drop synonym DBA_INMEMORY_AIMTASKS
/

drop synonym CDB_INMEMORY_AIMTASKS
/

drop synonym DBA_INMEMORY_AIMTASKDETAILS
/

drop synonym CDB_INMEMORY_AIMTASKDETAILS
/

drop synonym REPORT_FILES
/

drop synonym DBA_NETWORK_ACLS
/

drop synonym CDB_NETWORK_ACLS
/

drop synonym DBA_NETWORK_ACL_PRIVILEGES
/

drop synonym CDB_NETWORK_ACL_PRIVILEGES
/

drop synonym USER_NETWORK_ACL_PRIVILEGES
/

drop synonym DBA_HOST_ACLS
/

drop synonym CDB_HOST_ACLS
/

drop synonym DBA_WALLET_ACLS
/

drop synonym CDB_WALLET_ACLS
/

drop synonym DBA_HOST_ACES
/

drop synonym CDB_HOST_ACES
/

drop synonym DBA_WALLET_ACES
/

drop synonym CDB_WALLET_ACES
/

drop synonym USER_HOST_ACES
/

drop synonym USER_WALLET_ACES
/

drop synonym DBA_ACL_NAME_MAP
/

drop synonym CDB_ACL_NAME_MAP
/

drop synonym DBMS_NETWORK_ACL_ADMIN
/

drop synonym DBMS_NETWORK_ACL_UTILITY
/

drop synonym DBMS_WLM
/

drop synonym WLM_CAPABILITY_OBJECT
/

drop synonym WLM_CAPABILITY_ARRAY
/

drop synonym UNIFIED_AUDIT_TRAIL
/

drop synonym CDB_UNIFIED_AUDIT_TRAIL
/

drop synonym DBA_XS_AUDIT_TRAIL
/

drop synonym CDB_XS_AUDIT_TRAIL
/

drop synonym DBMS_AUDIT_UTIL
/

drop synonym DBMS_SYNC_REFRESH
/

drop synonym DBMS_IREFSTATS
/

drop synonym DBMS_MVIEW_STATS
/

drop synonym DBMS_REPCAT
/

drop synonym KUPUTIL
/

drop synonym XS_ADMIN_INT
/

drop synonym XS_ADMIN_UTIL
/

drop synonym XS$NAME_LIST
/

drop synonym XS$LIST
/

drop synonym UTL_RAW
/

drop synonym DBMS_ALERT
/

drop synonym DBMSZEXP_SYSPKGGRNT
/

drop synonym DBMS_STAT_FUNCS_AUX
/

drop synonym PBSDE
/

drop synonym DBMS_PSWMG_IMPORT
/

drop synonym DBMS_SERVICE_CONST
/

drop synonym DBMS_SERVICE_ERR
/

drop synonym DBA_KEEPSIZES
/

drop synonym CDB_KEEPSIZES
/

drop synonym DBMS_AQJMS_INTERNAL
/

drop synonym DBMS_LOG
/

drop synonym DBMS_RULE_EXP_EC_INTERNAL
/

drop synonym DBMS_RULE_EXP_RS_INTERNAL
/

drop synonym DBMS_RULE_EXP_RL_INTERNAL
/

drop synonym DBMS_RULE_EXP_EV_CTXS
/

drop synonym DBMS_RULE_EXP_RULE_SETS
/

drop synonym DBMS_RULE_EXP_RULES
/

drop synonym DBMS_RULE_IMP_OBJ
/

drop synonym DBMS_SUM_RWEQ_EXPORT_INTERNAL
/

drop synonym DBMS_SUM_RWEQ_EXPORT
/

drop synonym DMP_SYS
/

drop synonym DBMS_DM_MODEL_IMP
/

drop synonym ORA_DM_BUILD_OROWS
/

drop synonym ORA_DM_BUILD
/

drop synonym ORA_DM_BUILD_FLAT_OROWS
/

drop synonym ORA_DM_BUILD_FLAT
/

drop synonym ORA_DMSB_NODES
/

drop synonym ORA_FI_SUPERVISED_BINNING
/

drop synonym ODM_MODEL_UTIL
/

drop synonym ODM_UTIL
/

drop synonym DBMS_LOB_AM_PRIVATE
/

drop synonym XS$KEY_TYPE
/

drop synonym XS$KEY_LIST
/

drop synonym XS_DATA_SECURITY
/

drop synonym XS_DATA_SECURITY_UTIL
/

drop synonym XS$REALM_CONSTRAINT_TYPE
/

drop synonym XS$REALM_CONSTRAINT_LIST
/

drop synonym XS$COLUMN_CONSTRAINT_TYPE
/

drop synonym XS$COLUMN_CONSTRAINT_LIST
/

drop synonym XS_ROLESET
/

drop synonym XS_SECURITY_CLASS
/

drop synonym XS$PRIVILEGE
/

drop synonym XS$PRIVILEGE_LIST
/

drop synonym XS_ACL
/

drop synonym XS$ACE_TYPE
/

drop synonym XS$ACE_LIST
/

drop synonym XS_NAMESPACE
/

drop synonym XS$NS_ATTRIBUTE
/

drop synonym XS$NS_ATTRIBUTE_LIST
/

drop synonym XS_DIAG
/

drop synonym XS$VALIDATION_TABLE
/

drop synonym DBMS_SCN
/

drop synonym DBMS_BDSQL
/

drop synonym DATAPUMP_PATHS_VERSION
/

drop synonym DATAPUMP_PATHS
/

drop synonym DATAPUMP_PATHMAP
/

drop synonym DATAPUMP_TABLE_DATA
/

drop synonym DATAPUMP_OBJECT_CONNECT
/

drop synonym DBA_EXPORT_OBJECTS
/

drop synonym TABLE_EXPORT_OBJECTS
/

drop synonym SCHEMA_EXPORT_OBJECTS
/

drop synonym DATABASE_EXPORT_OBJECTS
/

drop synonym TABLESPACE_EXPORT_OBJECTS
/

drop synonym TRANSPORTABLE_EXPORT_OBJECTS
/

drop synonym DBA_EXPORT_PATHS
/

drop synonym TABLE_EXPORT_PATHS
/

drop synonym SCHEMA_EXPORT_PATHS
/

drop synonym DATABASE_EXPORT_PATHS
/

drop synonym TABLESPACE_EXPORT_PATHS
/

drop synonym TRANSPORTABLE_EXPORT_PATHS
/

drop synonym DATAPUMP_REMAP_OBJECTS
/

drop synonym DBMS_METADATA_TRANSFORMS
/

drop synonym DBMS_METADATA_TRANSFORM_PARAMS
/

drop synonym DBMS_METADATA_PARSE_ITEMS
/

drop synonym CDB_RPP$X$KCCAL
/

drop synonym CDB_ROPP$X$KCCAL
/

drop synonym CDB_RPP$X$KCCBS
/

drop synonym CDB_ROPP$X$KCCBS
/

drop synonym CDB_RPP$X$KCCBP
/

drop synonym CDB_ROPP$X$KCCBP
/

drop synonym CDB_RPP$X$KCCBF
/

drop synonym CDB_ROPP$X$KCCBF
/

drop synonym CDB_RPP$X$KCCBL
/

drop synonym CDB_ROPP$X$KCCBL
/

drop synonym CDB_RPP$X$KCCBI
/

drop synonym CDB_ROPP$X$KCCBI
/

drop synonym CDB_RPP$X$KCCDC
/

drop synonym CDB_ROPP$X$KCCDC
/

drop synonym CDB_RPP$X$KCCPD
/

drop synonym CDB_ROPP$X$KCCPD
/

drop synonym CDB_RPP$X$KCCPA
/

drop synonym CDB_ROPP$X$KCCPA
/

drop synonym CDB_RPP$X$KCCDI
/

drop synonym CDB_ROPP$X$KCCDI
/

drop synonym CDB_RPP$X$KCCDI2
/

drop synonym CDB_ROPP$X$KCCDI2
/

drop synonym CDB_RPP$X$KCCIC
/

drop synonym CDB_ROPP$X$KCCIC
/

drop synonym CDB_RPP$X$KCCPDB
/

drop synonym CDB_ROPP$X$KCCPDB
/

drop synonym CDB_RPP$X$KCPDBINC
/

drop synonym CDB_ROPP$X$KCPDBINC
/

drop synonym CDB_RPP$X$KCCTS
/

drop synonym CDB_ROPP$X$KCCTS
/

drop synonym CDB_RPP$X$KCCFE
/

drop synonym CDB_ROPP$X$KCCFE
/

drop synonym CDB_RPP$X$KCCFN
/

drop synonym CDB_ROPP$X$KCCFN
/

drop synonym CDB_RPP$X$KCVDF
/

drop synonym CDB_ROPP$X$KCVDF
/

drop synonym CDB_RPP$X$KCCTF
/

drop synonym CDB_ROPP$X$KCCTF
/

drop synonym CDB_RPP$X$KCVFH
/

drop synonym CDB_ROPP$X$KCVFH
/

drop synonym CDB_RPP$X$KCVFHTMP
/

drop synonym CDB_ROPP$X$KCVFHTMP
/

drop synonym CDB_RPP$X$KCVFHALL
/

drop synonym CDB_ROPP$X$KCVFHALL
/

drop synonym CDB_RPP$X$KCCRT
/

drop synonym CDB_ROPP$X$KCCRT
/

drop synonym CDB_RPP$X$KCCLE
/

drop synonym CDB_ROPP$X$KCCLE
/

drop synonym CDB_RPP$X$KCCSL
/

drop synonym CDB_ROPP$X$KCCSL
/

drop synonym CDB_RPP$X$KCCTIR
/

drop synonym CDB_ROPP$X$KCCTIR
/

drop synonym CDB_RPP$X$KCCOR
/

drop synonym CDB_ROPP$X$KCCOR
/

drop synonym CDB_RPP$X$KCCLH
/

drop synonym CDB_ROPP$X$KCCLH
/

drop synonym CDB_RPP$X$KCCPIC
/

drop synonym CDB_ROPP$X$KCCPIC
/

drop synonym CDB_RPP$X$KCCBLKCOR
/

drop synonym CDB_ROPP$X$KCCBLKCOR
/

drop synonym CDB_RPP$X$KCCCC
/

drop synonym CDB_ROPP$X$KCCCC
/

drop synonym CDB_RPP$X$KCCFC
/

drop synonym CDB_ROPP$X$KCCFC
/

drop synonym CDB_RPP$X$KCCRSR
/

drop synonym CDB_ROPP$X$KCCRSR
/

drop synonym CDB_RPP$X$KCCTKH
/

drop synonym CDB_ROPP$X$KCCTKH
/

drop synonym HS_FDS_CLASS
/

drop synonym HS_FDS_INST
/

drop synonym HS_BASE_CAPS
/

drop synonym HS_CLASS_CAPS
/

drop synonym HS_INST_CAPS
/

drop synonym HS_BASE_DD
/

drop synonym HS_CLASS_DD
/

drop synonym HS_INST_DD
/

drop synonym HS_CLASS_INIT
/

drop synonym HS_INST_INIT
/

drop synonym HS_ALL_CAPS
/

drop synonym HS_ALL_DD
/

drop synonym HS_ALL_INITS
/

drop synonym HS_FDS_CLASS_DATE
/

drop synonym DBMS_HS
/

drop synonym HS_PARALLEL_METADATA
/

drop synonym HS_PARALLEL_PARTITION_DATA
/

drop synonym HS_PARALLEL_HISTOGRAM_DATA
/

drop synonym HS_PARALLEL_SAMPLE_DATA
/

drop synonym DBMS_HS_PARALLEL
/

drop synonym DBMS_AW$_COLUMNLIST_T
/

drop synonym DBMS_AW$_DIMENSION_SOURCE_T
/

drop synonym DBMS_AW$_DIMENSION_SOURCES_T
/

drop synonym DBMS_AW
/

drop synonym OLAP_TABLE
/

drop synonym CUBE_TABLE
/

drop synonym OLAPRC_TABLE
/

drop synonym OLAP_SRF_T
/

drop synonym OLAP_NUMBER_SRF
/

drop synonym OLAP_EXPRESSION
/

drop synonym OLAP_TEXT_SRF
/

drop synonym OLAP_EXPRESSION_TEXT
/

drop synonym OLAP_DATE_SRF
/

drop synonym OLAP_EXPRESSION_DATE
/

drop synonym OLAP_BOOL_SRF
/

drop synonym OLAP_EXPRESSION_BOOL
/

drop synonym OLAP_CONDITION
/

drop synonym DBMS_AW_EXP
/

drop synonym DBMS_AW_STATS
/

drop synonym DBMS_CUBE_LOG
/

drop synonym GV$MVREFRESH
/

drop synonym V$MVREFRESH
/

drop synonym WLM_METRICS_STREAM
/

drop synonym WLM_CLASSIFIER_PLAN
/

drop synonym WLM_MPA_STREAM
/

drop synonym WLM_VIOLATION_STREAM
/

drop synonym OWA
/

drop synonym HTF
/

drop synonym HTP
/

drop synonym OWA_COOKIE
/

drop synonym OWA_IMAGE
/

drop synonym OWA_OPT_LOCK
/

drop synonym OWA_PATTERN
/

drop synonym OWA_SEC
/

drop synonym OWA_TEXT
/

drop synonym OWA_UTIL
/

drop synonym OWA_INIT
/

drop synonym OWA_CACHE
/

drop synonym OWA_MATCH
/

drop synonym WPG_DOCLOAD
/

drop synonym OWA_CUSTOM
/

drop synonym OWA_GLOBAL
/

drop synonym V$SQL_BIND_CAPTURE
/

drop synonym GV$SQL_BIND_CAPTURE
/

drop synonym LOCAL_TABLE_FAMILY_SERVICES
/

drop synonym LOCAL_CHUNK_TYPES
/

drop synonym LOCAL_CHUNK_COLUMNS
/

drop synonym LOCAL_CHUNKS
/

drop synonym SHA_DATABASES
/

drop synonym XDB$STRING_LIST_T
/

drop synonym DBMS_XMLSCHEMA
/

drop synonym DBMS_XDBZ
/

drop synonym UTL_BINARYINPUTSTREAM
/

drop synonym UTL_BINARYOUTPUTSTREAM
/

drop synonym UTL_CHARACTERINPUTSTREAM
/

drop synonym UTL_CHARACTEROUTPUTSTREAM
/

drop synonym XMLBINARYINPUTSTREAM
/

drop synonym XMLBINARYOUTPUTSTREAM
/

drop synonym XMLCHARACTERINPUTSTREAM
/

drop synonym XMLCHARACTEROUTPUTSTREAM
/

drop synonym DBMS_XMLDOM
/

drop synonym XMLDOM
/

drop synonym DBMS_XDBRESOURCE
/

drop synonym DBMS_XDB
/

drop synonym DBMS_XDB_CONFIG
/

drop synonym DBMS_XDB_REPOS
/

drop synonym DBMS_XDB_ADMIN
/

drop synonym DBMS_CSX_ADMIN
/

drop synonym DBMS_XLSB
/

drop synonym DBMS_XMLSCHEMA_TABMD
/

drop synonym DBMS_XMLSCHEMA_TABMDARR
/

drop synonym DBMS_XMLSCHEMA_RESMD
/

drop synonym DBMS_XMLSCHEMA_RESMDARR
/

drop synonym DBMS_XMLSCHEMA_LSB
/

drop synonym DBMS_XMLPARSER
/

drop synonym XMLPARSER
/

drop synonym DBMS_XSLPROCESSOR
/

drop synonym XSLPROCESSOR
/

drop synonym DBMS_CLOBUTIL
/

drop synonym USER_XML_PARTITIONED_TABLE_OK
/

drop synonym DBMS_XDBUTIL_INT
/

drop synonym DBMS_XDB_PRINT
/

drop synonym DBMS_CSX_INT
/

drop synonym DBMS_CSX_INT2
/

drop synonym DBMS_JSON
/

drop synonym JSON_DATAGUIDE
/

drop synonym JSON_HIERDATAGUIDE
/

drop synonym SYS_DGAGG
/

drop synonym SYS_HIERDGAGG
/

drop synonym KCISYS_CTXAGG
/

drop synonym DBA_JSON_DATAGUIDES
/

drop synonym CDB_JSON_DATAGUIDES
/

drop synonym USER_JSON_DATAGUIDES
/

drop synonym ALL_JSON_DATAGUIDES
/

drop synonym DBA_JSON_DATAGUIDE_FIELDS
/

drop synonym CDB_JSON_DATAGUIDE_FIELDS
/

drop synonym USER_JSON_DATAGUIDE_FIELDS
/

drop synonym ALL_JSON_DATAGUIDE_FIELDS
/

drop synonym UNDER_PATH
/

drop synonym EQUALS_PATH
/

drop synonym PATH
/

drop synonym DEPTH
/

drop synonym ABSPATH
/

drop synonym RESOURCE_VIEW
/

drop synonym XDB_RVTRIG_PKG
/

drop synonym CONTENTSCHEMAIS
/

drop synonym XDS_ACL
/

drop synonym XDS_ACE
/

drop synonym DBMS_XDB_VERSION
/

drop synonym ALL_PATH
/

drop synonym PATH_VIEW
/

drop synonym XDB_PVTRIG_PKG
/

drop synonym DOCUMENT_LINKS
/

drop synonym DBMS_XMLINDEX
/

drop synonym XIMETADATA_PKG
/

drop synonym DBA_XML_TABLES
/

drop synonym CDB_XML_TABLES
/

drop synonym ALL_XML_TABLES
/

drop synonym USER_XML_TABLES
/

drop synonym DBA_XML_TAB_COLS
/

drop synonym CDB_XML_TAB_COLS
/

drop synonym ALL_XML_TAB_COLS
/

drop synonym USER_XML_TAB_COLS
/

drop synonym DBA_XML_VIEWS
/

drop synonym CDB_XML_VIEWS
/

drop synonym ALL_XML_VIEWS
/

drop synonym USER_XML_VIEWS
/

drop synonym DBA_XML_VIEW_COLS
/

drop synonym CDB_XML_VIEW_COLS
/

drop synonym ALL_XML_VIEW_COLS
/

drop synonym USER_XML_VIEW_COLS
/

drop synonym DBA_XML_SCHEMAS
/

drop synonym CDB_XML_SCHEMAS
/

drop synonym ALL_XML_SCHEMAS
/

drop synonym ALL_XML_SCHEMAS2
/

drop synonym USER_XML_SCHEMAS
/

drop synonym DBA_XML_INDEXES
/

drop synonym CDB_XML_INDEXES
/

drop synonym ALL_XML_INDEXES
/

drop synonym USER_XML_INDEXES
/

drop synonym USER_XML_COLUMN_NAMES
/

drop synonym DBA_XML_SCHEMA_IMPORTS
/

drop synonym CDB_XML_SCHEMA_IMPORTS
/

drop synonym DBA_XML_SCHEMA_INCLUDES
/

drop synonym CDB_XML_SCHEMA_INCLUDES
/

drop synonym DBA_XML_SCHEMA_DEPENDENCY
/

drop synonym CDB_XML_SCHEMA_DEPENDENCY
/

drop synonym CDB_XMLSCHEMA_LEVEL_VIEW_DUP
/

drop synonym DBA_XMLSCHEMA_LEVEL_VIEW
/

drop synonym CDB_XMLSCHEMA_LEVEL_VIEW
/

drop synonym DBA_XML_SCHEMA_NAMESPACES
/

drop synonym CDB_XML_SCHEMA_NAMESPACES
/

drop synonym ALL_XML_SCHEMA_NAMESPACES
/

drop synonym USER_XML_SCHEMA_NAMESPACES
/

drop synonym DBA_XML_SCHEMA_ELEMENTS
/

drop synonym CDB_XML_SCHEMA_ELEMENTS
/

drop synonym ALL_XML_SCHEMA_ELEMENTS
/

drop synonym USER_XML_SCHEMA_ELEMENTS
/

drop synonym DBA_XML_SCHEMA_SUBSTGRP_MBRS
/

drop synonym CDB_XML_SCHEMA_SUBSTGRP_MBRS
/

drop synonym ALL_XML_SCHEMA_SUBSTGRP_MBRS
/

drop synonym USER_XML_SCHEMA_SUBSTGRP_MBRS
/

drop synonym DBA_XML_SCHEMA_SUBSTGRP_HEAD
/

drop synonym CDB_XML_SCHEMA_SUBSTGRP_HEAD
/

drop synonym ALL_XML_SCHEMA_SUBSTGRP_HEAD
/

drop synonym USER_XML_SCHEMA_SUBSTGRP_HEAD
/

drop synonym DBA_XML_SCHEMA_COMPLEX_TYPES
/

drop synonym CDB_XML_SCHEMA_COMPLEX_TYPES
/

drop synonym ALL_XML_SCHEMA_COMPLEX_TYPES
/

drop synonym USER_XML_SCHEMA_COMPLEX_TYPES
/

drop synonym DBA_XML_SCHEMA_SIMPLE_TYPES
/

drop synonym CDB_XML_SCHEMA_SIMPLE_TYPES
/

drop synonym ALL_XML_SCHEMA_SIMPLE_TYPES
/

drop synonym USER_XML_SCHEMA_SIMPLE_TYPES
/

drop synonym DBA_XML_SCHEMA_ATTRIBUTES
/

drop synonym CDB_XML_SCHEMA_ATTRIBUTES
/

drop synonym ALL_XML_SCHEMA_ATTRIBUTES
/

drop synonym USER_XML_SCHEMA_ATTRIBUTES
/

drop synonym DBA_XML_OUT_OF_LINE_TABLES
/

drop synonym CDB_XML_OUT_OF_LINE_TABLES
/

drop synonym ALL_XML_OUT_OF_LINE_TABLES
/

drop synonym USER_XML_OUT_OF_LINE_TABLES
/

drop synonym DBA_XMLTYPE_COLS
/

drop synonym CDB_XMLTYPE_COLS
/

drop synonym ALL_XMLTYPE_COLS
/

drop synonym USER_XMLTYPE_COLS
/

drop synonym DBA_XML_NESTED_TABLES
/

drop synonym CDB_XML_NESTED_TABLES
/

drop synonym ALL_XML_NESTED_TABLES
/

drop synonym USER_XML_NESTED_TABLES
/

drop synonym DBMS_RESCONFIG
/

drop synonym DBMS_XEVENT
/

drop synonym DBMS_XMLTRANSLATIONS
/

drop synonym USER_SODA_COLLECTIONS
/

drop synonym DBMS_SODA_ADMIN
/

drop synonym DBMS_SODA_DOM
/

drop synonym DBMS_SODA_USER_ADMIN
/

drop synonym SODA_DOCUMENT_T
/

drop synonym SODA_DOCUMENT_LIST_T
/

drop synonym SODA_CURSOR_T
/

drop synonym SODA_KEY_LIST_T
/

drop synonym SODA_OPERATION_T
/

drop synonym SODA_COLLECTION_T
/

drop synonym SODA_COLLNAME_LIST_T
/

drop synonym DBMS_SODA
/

drop synonym DBMS_XDB_CONSTANTS
/

drop synonym DBMS_XMLSCHEMA_ANNOTATE
/

drop synonym DBMS_XMLSTORAGE_MANAGE
/

drop synonym DBMS_XDB_CONTENT
/

drop synonym DBA_MVREF_STATS_SYS_DEFAULTS
/

drop synonym USER_MVREF_STATS_SYS_DEFAULTS
/

drop synonym CDB_MVREF_STATS_SYS_DEFAULTS
/

drop synonym DBA_MVREF_STATS_PARAMS
/

drop synonym USER_MVREF_STATS_PARAMS
/

drop synonym CDB_MVREF_STATS_PARAMS
/

drop synonym DBA_MVREF_RUN_STATS
/

drop synonym USER_MVREF_RUN_STATS
/

drop synonym CDB_MVREF_RUN_STATS
/

drop synonym DBA_MVREF_CHANGE_STATS
/

drop synonym USER_MVREF_CHANGE_STATS
/

drop synonym CDB_MVREF_CHANGE_STATS
/

drop synonym DBA_MVREF_STMT_STATS
/

drop synonym USER_MVREF_STMT_STATS
/

drop synonym CDB_MVREF_STMT_STATS
/

drop synonym DBA_MVREF_STATS
/

drop synonym USER_MVREF_STATS
/

drop synonym CDB_MVREF_STATS
/

drop synonym DBA_REGISTRY_SQLPATCH
/

drop synonym CDB_REGISTRY_SQLPATCH
/

drop synonym DBA_REGISTRY_SQLPATCH_RU_INFO
/

drop synonym CDB_REGISTRY_SQLPATCH_RU_INFO
/

drop synonym DBMS_SQLPATCH
/

drop synonym USER_EPG_DAD_AUTHORIZATION
/

drop synonym DBA_EPG_DAD_AUTHORIZATION
/

drop synonym CDB_EPG_DAD_AUTHORIZATION
/

drop synonym DBMS_EPG
/

drop synonym EXT_TO_OBJ
/

drop synonym V$GES_STATISTICS
/

drop synonym V$GES_LATCH
/

drop synonym V$GES_CONVERT_LOCAL
/

drop synonym V$GES_CONVERT_REMOTE
/

drop synonym V$GES_TRAFFIC_CONTROLLER
/

drop synonym V$GES_RESOURCE
/

drop synonym GV$GES_STATISTICS
/

drop synonym GV$GES_LATCH
/

drop synonym GV$GES_CONVERT_LOCAL
/

drop synonym GV$GES_CONVERT_REMOTE
/

drop synonym GV$GES_TRAFFIC_CONTROLLER
/

drop synonym GV$GES_RESOURCE
/

drop synonym DBMS_CRYPTO_TOOLKIT
/

drop synonym DBMS_WM
/

drop synonym ALL_MP_GRAPH_WORKSPACES
/

drop synonym ALL_MP_PARENT_WORKSPACES
/

drop synonym ALL_REMOVED_WORKSPACES
/

drop synonym ALL_VERSION_HVIEW
/

drop synonym ALL_WM_CONSTRAINTS
/

drop synonym ALL_WM_CONSTRAINT_VIOLATIONS
/

drop synonym ALL_WM_CONS_COLUMNS
/

drop synonym ALL_WM_IND_COLUMNS
/

drop synonym ALL_WM_IND_EXPRESSIONS
/

drop synonym ALL_WM_LOCKED_TABLES
/

drop synonym ALL_WM_MODIFIED_TABLES
/

drop synonym ALL_WM_POLICIES
/

drop synonym ALL_WM_RIC_INFO
/

drop synonym ALL_WM_TAB_TRIGGERS
/

drop synonym ALL_WM_VERSIONED_TABLES
/

drop synonym ALL_WM_VT_ERRORS
/

drop synonym ALL_WORKSPACES
/

drop synonym ALL_WORKSPACE_PRIVS
/

drop synonym ALL_WORKSPACE_SAVEPOINTS
/

drop synonym CDB_REMOVED_WORKSPACES
/

drop synonym CDB_WM_SYS_PRIVS
/

drop synonym CDB_WM_VERSIONED_TABLES
/

drop synonym CDB_WM_VT_ERRORS
/

drop synonym CDB_WORKSPACES
/

drop synonym CDB_WORKSPACE_PRIVS
/

drop synonym CDB_WORKSPACE_SAVEPOINTS
/

drop synonym CDB_WORKSPACE_SESSIONS
/

drop synonym DBA_REMOVED_WORKSPACES
/

drop synonym DBA_WM_SYS_PRIVS
/

drop synonym DBA_WM_VERSIONED_TABLES
/

drop synonym DBA_WM_VT_ERRORS
/

drop synonym DBA_WORKSPACES
/

drop synonym DBA_WORKSPACE_PRIVS
/

drop synonym DBA_WORKSPACE_SAVEPOINTS
/

drop synonym DBA_WORKSPACE_SESSIONS
/

drop synonym ROLE_WM_PRIVS
/

drop synonym USER_MP_GRAPH_WORKSPACES
/

drop synonym USER_MP_PARENT_WORKSPACES
/

drop synonym USER_REMOVED_WORKSPACES
/

drop synonym USER_WM_CONSTRAINTS
/

drop synonym USER_WM_CONS_COLUMNS
/

drop synonym USER_WM_IND_COLUMNS
/

drop synonym USER_WM_IND_EXPRESSIONS
/

drop synonym USER_WM_LOCKED_TABLES
/

drop synonym USER_WM_MODIFIED_TABLES
/

drop synonym USER_WM_PRIVS
/

drop synonym USER_WM_POLICIES
/

drop synonym USER_WM_RIC_INFO
/

drop synonym USER_WM_TAB_TRIGGERS
/

drop synonym USER_WM_VERSIONED_TABLES
/

drop synonym USER_WM_VT_ERRORS
/

drop synonym USER_WORKSPACES
/

drop synonym USER_WORKSPACE_PRIVS
/

drop synonym USER_WORKSPACE_SAVEPOINTS
/

drop synonym WM_COMPRESSIBLE_TABLES
/

drop synonym WM_COMPRESS_BATCH_SIZES
/

drop synonym WM_EVENTS_INFO
/

drop synonym WM_INSTALLATION
/

drop synonym WM_REPLICATION_INFO
/

drop synonym WM_CONTAINS
/

drop synonym WM_EQUALS
/

drop synonym WM_GREATERTHAN
/

drop synonym WM_INTERSECTION
/

drop synonym WM_LDIFF
/

drop synonym WM_LESSTHAN
/

drop synonym WM_MEETS
/

drop synonym WM_OVERLAPS
/

drop synonym WM_PERIOD
/

drop synonym WM_RDIFF
/

drop synonym PRODUCT_PROFILE
/

drop synonym PRODUCT_USER_PROFILE
/

drop synonym JAVASNM
/

drop synonym DBMS_JAVA
/

drop synonym "NameFromLastDDL"
/

drop synonym DBJ_SHORT_NAME
/

drop synonym DBMS_JAVASCRIPT
/

drop synonym GET_ERROR$
/

drop synonym DBA_JAVA_POLICY
/

drop synonym USER_JAVA_POLICY
/

drop synonym USER_JAVA_CLASSES
/

drop synonym ALL_JAVA_CLASSES
/

drop synonym DBA_JAVA_CLASSES
/

drop synonym CDB_JAVA_CLASSES
/

drop synonym USER_JAVA_LAYOUTS
/

drop synonym ALL_JAVA_LAYOUTS
/

drop synonym DBA_JAVA_LAYOUTS
/

drop synonym CDB_JAVA_LAYOUTS
/

drop synonym USER_JAVA_IMPLEMENTS
/

drop synonym ALL_JAVA_IMPLEMENTS
/

drop synonym DBA_JAVA_IMPLEMENTS
/

drop synonym CDB_JAVA_IMPLEMENTS
/

drop synonym USER_JAVA_INNERS
/

drop synonym ALL_JAVA_INNERS
/

drop synonym DBA_JAVA_INNERS
/

drop synonym CDB_JAVA_INNERS
/

drop synonym USER_JAVA_FIELDS
/

drop synonym ALL_JAVA_FIELDS
/

drop synonym DBA_JAVA_FIELDS
/

drop synonym CDB_JAVA_FIELDS
/

drop synonym USER_JAVA_METHODS
/

drop synonym ALL_JAVA_METHODS
/

drop synonym DBA_JAVA_METHODS
/

drop synonym CDB_JAVA_METHODS
/

drop synonym USER_JAVA_ARGUMENTS
/

drop synonym ALL_JAVA_ARGUMENTS
/

drop synonym DBA_JAVA_ARGUMENTS
/

drop synonym CDB_JAVA_ARGUMENTS
/

drop synonym USER_JAVA_THROWS
/

drop synonym ALL_JAVA_THROWS
/

drop synonym DBA_JAVA_THROWS
/

drop synonym CDB_JAVA_THROWS
/

drop synonym USER_JAVA_DERIVATIONS
/

drop synonym ALL_JAVA_DERIVATIONS
/

drop synonym DBA_JAVA_DERIVATIONS
/

drop synonym CDB_JAVA_DERIVATIONS
/

drop synonym USER_JAVA_RESOLVERS
/

drop synonym ALL_JAVA_RESOLVERS
/

drop synonym DBA_JAVA_RESOLVERS
/

drop synonym CDB_JAVA_RESOLVERS
/

drop synonym USER_JAVA_NCOMPS
/

drop synonym ALL_JAVA_NCOMPS
/

drop synonym DBA_JAVA_NCOMPS
/

drop synonym CDB_JAVA_NCOMPS
/

drop synonym USER_JAVA_COMPILER_OPTIONS
/

drop synonym ALL_JAVA_COMPILER_OPTIONS
/

drop synonym DBA_JAVA_COMPILER_OPTIONS
/

drop synonym CDB_JAVA_COMPILER_OPTIONS
/

drop synonym CDB_JAVA_POLICY
/

drop synonym JAVA_XA
/

drop synonym DBMS_JVM_EXP_PERMS
/

drop synonym OJDS_NAMESPACE
/

drop synonym "OracleXML"
/

drop synonym "OracleXMLStore"
/

drop synonym DBMS_XMLQUERY
/

drop synonym DBMS_XMLSAVE
/

drop synonym DBMS_XQUERY
/

drop synonym CTX_PARAMETERS
/

drop synonym CTX_CLASSES
/

drop synonym CTX_OBJECTS
/

drop synonym CTX_OBJECT_ATTRIBUTES
/

drop synonym CTX_OBJECT_ATTRIBUTE_LOV
/

drop synonym CTX_PREFERENCES
/

drop synonym CTX_USER_PREFERENCES
/

drop synonym CTX_PREFERENCE_VALUES
/

drop synonym CTX_USER_PREFERENCE_VALUES
/

drop synonym CTX_USER_INDEXES
/

drop synonym CTX_USER_INDEX_PARTITIONS
/

drop synonym CTX_USER_INDEX_VALUES
/

drop synonym CTX_USER_INDEX_SUB_LEXERS
/

drop synonym CTX_USER_INDEX_SUB_LEXER_VALS
/

drop synonym CTX_USER_INDEX_OBJECTS
/

drop synonym CTX_SQES
/

drop synonym CTX_USER_SQES
/

drop synonym CTX_THESAURI
/

drop synonym CTX_USER_THESAURI
/

drop synonym CTX_THES_PHRASES
/

drop synonym CTX_USER_THES_PHRASES
/

drop synonym CTX_SECTION_GROUPS
/

drop synonym CTX_USER_SECTION_GROUPS
/

drop synonym CTX_SECTIONS
/

drop synonym CTX_USER_SECTIONS
/

drop synonym CTX_STOPLISTS
/

drop synonym CTX_USER_STOPLISTS
/

drop synonym CTX_STOPWORDS
/

drop synonym CTX_USER_STOPWORDS
/

drop synonym CTX_SUB_LEXERS
/

drop synonym CTX_USER_SUB_LEXERS
/

drop synonym CTX_INDEX_SETS
/

drop synonym CTX_USER_INDEX_SETS
/

drop synonym CTX_INDEX_SET_INDEXES
/

drop synonym CTX_USER_INDEX_SET_INDEXES
/

drop synonym CTX_USER_PENDING
/

drop synonym CTX_USER_INDEX_ERRORS
/

drop synonym CTX_TRACE_VALUES
/

drop synonym CTX_FILTER_CACHE_STATISTICS
/

drop synonym CTX_USER_FILTER_BY_COLUMNS
/

drop synonym CTX_USER_ORDER_BY_COLUMNS
/

drop synonym CTX_USER_EXTRACT_RULES
/

drop synonym CTX_USER_EXTRACT_STOP_ENTITIES
/

drop synonym CTX_USER_EXTRACT_POLICIES
/

drop synonym CTX_USER_EXTRACT_POLICY_VALUES
/

drop synonym CTX_USER_AUTO_OPTIMIZE_INDEXES
/

drop synonym CTX_INDEX_SECTIONS
/

drop synonym CTX_USER_INDEX_SECTIONS
/

drop synonym CTX_CENTROIDS
/

drop synonym CTX_USER_SESSION_SQES
/

drop synonym CTX_DOC
/

drop synonym CTX_DDL
/

drop synonym CTX_OUTPUT
/

drop synonym CTX_QUERY
/

drop synonym CTX_THES
/

drop synonym CTX_REPORT
/

drop synonym CTX_ULEXER
/

drop synonym CTX_CLS
/

drop synonym CTX_ENTITY
/

drop synonym CTX_TREE
/

drop synonym CTX_ANL
/

drop synonym DRVODM
/

drop synonym CONTAINS
/

drop synonym SCORE
/

drop synonym CATSEARCH
/

drop synonym MATCHES
/

drop synonym MATCH_SCORE
/

drop synonym DBMS_XDBT
/

drop synonym SI_COLOR
/

drop synonym SI_STILLIMAGE
/

drop synonym SI_AVERAGECOLOR
/

drop synonym SI_COLORHISTOGRAM
/

drop synonym SI_POSITIONALCOLOR
/

drop synonym SI_TEXTURE
/

drop synonym SI_FEATURELIST
/

drop synonym ORDAUDIO
/

drop synonym ORDIMAGE
/

drop synonym ORDVIDEO
/

drop synonym ORDDOC
/

drop synonym ORDIMAGESIGNATURE
/

drop synonym ORDDICOM
/

drop synonym ORDDATASOURCE
/

drop synonym ORDPLSGWYUTIL
/

drop synonym SI_MKSTILLIMAGE1
/

drop synonym SI_MKSTILLIMAGE2
/

drop synonym ORA_SI_MKSTILLIMAGE
/

drop synonym SI_CHGCONTENT
/

drop synonym SI_CONVERTFORMAT
/

drop synonym SI_GETTHMBNL
/

drop synonym SI_GETSIZEDTHMBNL
/

drop synonym SI_GETCONTENT
/

drop synonym SI_GETCONTENTLNGTH
/

drop synonym SI_GETHEIGHT
/

drop synonym SI_GETWIDTH
/

drop synonym SI_GETFORMAT
/

drop synonym SI_MKRGBCLR
/

drop synonym SI_FINDAVGCLR
/

drop synonym SI_MKAVGCLR
/

drop synonym SI_SCOREBYAVGCLR
/

drop synonym SI_FINDCLRHSTGR
/

drop synonym SI_MKCLRHSTGR
/

drop synonym SI_ARRAYCLRHSTGR
/

drop synonym SI_APPENDCLRHSTGR
/

drop synonym SI_SCOREBYCLRHSTGR
/

drop synonym SI_FINDPSTNLCLR
/

drop synonym SI_SCOREBYPSTNLCLR
/

drop synonym SI_FINDTEXTURE
/

drop synonym SI_SCOREBYTEXTURE
/

drop synonym SI_MKFTRLIST
/

drop synonym SI_SETAVGCLRFTR
/

drop synonym SI_SETCLRHSTGRFTR
/

drop synonym SI_SETPSTNLCLRFTR
/

drop synonym SI_SETTEXTUREFTR
/

drop synonym SI_GETAVGCLRFTR
/

drop synonym SI_GETAVGCLRFTRW
/

drop synonym SI_GETCLRHSTGRFTR
/

drop synonym SI_GETCLRHSTGRFTRW
/

drop synonym SI_GETPSTNLCLRFTR
/

drop synonym SI_GETPSTNLCLRFTRW
/

drop synonym SI_GETTEXTUREFTR
/

drop synonym SI_GETTEXTUREFTRW
/

drop synonym SI_SCOREBYFTRLIST
/

drop synonym ORD_DICOM
/

drop synonym ORD_DICOM_ADMIN
/

drop synonym ORD_IMAGE
/

drop synonym ORD_AUDIO
/

drop synonym ORD_VIDEO
/

drop synonym ORD_DOC
/

drop synonym ORDDCM_DBRELEASE_DOCS
/

drop synonym ORDDCM_DOCUMENTS
/

drop synonym ORDDCM_DOCUMENT_TYPES
/

drop synonym ORDDCM_CONSTRAINT_NAMES
/

drop synonym ORDDCM_DOCUMENT_REFS
/

drop synonym ORDDCM_CONFORMANCE_VLD_MSGS
/

drop synonym SDO_KEYWORDARRAY
/

drop synonym SDO_ADDR_ARRAY
/

drop synonym SDO_GEO_ADDR
/

drop synonym SDO_GEOMETRY_ARRAY
/

drop synonym SDO_GEOMETRY
/

drop synonym SDO_POINT_TYPE
/

drop synonym SDO_ELEM_INFO_ARRAY
/

drop synonym SDO_ORDINATE_ARRAY
/

drop synonym SDO_DIM_ELEMENT
/

drop synonym SDO_DIM_ARRAY
/

drop synonym SDO_VPOINT_TYPE
/

drop synonym SDO_MBR
/

drop synonym SDO_NUMBER_ARRAY
/

drop synonym SDO_NUMBER_ARRAYSET
/

drop synonym SDO_STRING_ARRAY
/

drop synonym SDO_STRING2_ARRAY
/

drop synonym SDO_STRING2_ARRAYSET
/

drop synonym SDO_ROWIDPAIR
/

drop synonym SDO_ROWIDSET
/

drop synonym SDO_REGION
/

drop synonym SDO_REGIONSET
/

drop synonym SDO_REGAGGR
/

drop synonym SDO_REGAGGRSET
/

drop synonym SDO_RANGE
/

drop synonym SDO_RANGE_ARRAY
/

drop synonym SDO_CLOSEST_POINTS_TYPE
/

drop synonym TFM_PLAN
/

drop synonym SDO_TFM_CHAIN
/

drop synonym SDO_SRID
/

drop synonym SDO_TOPO_GEOMETRY_LAYER
/

drop synonym SDO_TOPO_GEOMETRY_LAYER_ARRAY
/

drop synonym SDO_TOPO_GEOMETRY_LAYER_TABLE
/

drop synonym SDO_LIST_TYPE
/

drop synonym SDO_TOPO_OBJECT
/

drop synonym SDO_TOPO_NSTD_TBL
/

drop synonym SDO_TGL_OBJECT
/

drop synonym SDO_EDGE_ARRAY
/

drop synonym SDO_TOPO_OBJECT_ARRAY
/

drop synonym SDO_TGL_OBJECT_ARRAY
/

drop synonym SDO_TOPO_GEOMETRY
/

drop synonym USER_SDO_GEOM_METADATA
/

drop synonym ALL_SDO_GEOM_METADATA
/

drop synonym SDO_VERSION
/

drop synonym SDO_OWM_INSTALLED
/

drop synonym SDO_SRS_NAMESPACE
/

drop synonym SDO_SRID_CHAIN
/

drop synonym TMP_COORD_OPS
/

drop synonym EPSG_PARAM
/

drop synonym EPSG_PARAMS
/

drop synonym NTV2_XML_DATA
/

drop synonym CS_SRS
/

drop synonym SDO_CS
/

drop synonym SDO_DATUM_ENGINEERING
/

drop synonym SDO_DATUM_GEODETIC
/

drop synonym SDO_DATUM_VERTICAL
/

drop synonym SDO_CRS_COMPOUND
/

drop synonym SDO_CRS_ENGINEERING
/

drop synonym SDO_CRS_GEOCENTRIC
/

drop synonym SDO_CRS_GEOGRAPHIC2D
/

drop synonym SDO_CRS_GEOGRAPHIC3D
/

drop synonym SDO_CRS_PROJECTED
/

drop synonym SDO_CRS_VERTICAL
/

drop synonym SDO_AREA_UNITS
/

drop synonym SDO_DIST_UNITS
/

drop synonym SDO_ANGLE_UNITS
/

drop synonym SDO_ELLIPSOIDS_OLD_FORMAT
/

drop synonym SDO_PROJECTIONS_OLD_FORMAT
/

drop synonym SDO_DATUMS_OLD_FORMAT
/

drop synonym SDO_COORD_OPS
/

drop synonym SDO_AVAILABLE_OPS
/

drop synonym SDO_AVAILABLE_ELEM_OPS
/

drop synonym SDO_AVAILABLE_NON_ELEM_OPS
/

drop synonym SDO_COORD_OP_PATHS
/

drop synonym SDO_PREFERRED_OPS_SYSTEM
/

drop synonym SDO_PREFERRED_OPS_USER
/

drop synonym SDO_COORD_REF_SYS
/

drop synonym SDO_COORD_REF_SYSTEM
/

drop synonym SDO_UNITS_OF_MEASURE
/

drop synonym SDO_PRIME_MERIDIANS
/

drop synonym SDO_ELLIPSOIDS
/

drop synonym SDO_DATUMS
/

drop synonym SDO_COORD_SYS
/

drop synonym SDO_COORD_AXES
/

drop synonym SDO_COORD_AXIS_NAMES
/

drop synonym SDO_COORD_OP_METHODS
/

drop synonym SDO_COORD_OP_PARAMS
/

drop synonym SDO_COORD_OP_PARAM_USE
/

drop synonym SDO_COORD_OP_PARAM_VALS
/

drop synonym SDO_SRIDS_BY_URN
/

drop synonym SDO_SRIDS_BY_URN_PATTERN
/

drop synonym SDO_TRANSIENT_RULE
/

drop synonym SDO_TRANSIENT_RULE_SET
/

drop synonym SDO_SRID_LIST
/

drop synonym SDO_ELLIPSOIDS_OLD_SNAPSHOT
/

drop synonym SDO_PROJECTIONS_OLD_SNAPSHOT
/

drop synonym SDO_DATUMS_OLD_SNAPSHOT
/

drop synonym MD
/

drop synonym SDO_FEATURE
/

drop synonym SDO_ST_TOLERANCE
/

drop synonym SDO_INDEX_HISTOGRAM_TABLE
/

drop synonym SDO_INDEX_HISTOGRAM
/

drop synonym SDO_INDEX_HISTOGRAMS
/

drop synonym USER_SDO_INDEX_HISTOGRAM
/

drop synonym USER_SDO_INDEX_HISTOGRAMS
/

drop synonym ALL_SDO_INDEX_HISTOGRAM
/

drop synonym ALL_SDO_INDEX_HISTOGRAMS
/

drop synonym MY_SDO_INDEX_METADATA
/

drop synonym SDO_INDEX_METADATA
/

drop synonym USER_SDO_INDEX_METADATA
/

drop synonym ALL_SDO_INDEX_METADATA
/

drop synonym USER_SDO_INDEX_INFO
/

drop synonym ALL_SDO_INDEX_INFO
/

drop synonym SDO_TXN_JOURNAL_GTT
/

drop synonym SDO_TXN_JOURNAL_REG
/

drop synonym SDO_DIST_METADATA_TABLE
/

drop synonym SDO_DIAG_MESSAGES_TABLE
/

drop synonym USER_SDO_DIAG_MESSAGES
/

drop synonym ALL_SDO_DIAG_MESSAGES
/

drop synonym SDO_TXN_IDX_EXP_UPD_RGN
/

drop synonym USER_SDO_LRS_METADATA
/

drop synonym ALL_SDO_LRS_METADATA
/

drop synonym USER_SDO_TOPO_METADATA
/

drop synonym ALL_SDO_TOPO_METADATA
/

drop synonym USER_SDO_TOPO_INFO
/

drop synonym ALL_SDO_TOPO_INFO
/

drop synonym SDO_TOPO_TRANSACT_DATA$
/

drop synonym SDO_TOPO_DATA$
/

drop synonym SDO_RELATEMASK_TABLE
/

drop synonym SDO_3GL
/

drop synonym SDO
/

drop synonym SDO_ADMIN
/

drop synonym OGIS_GEOMETRY_COLUMNS
/

drop synonym DBA_GEOMETRY_COLUMNS
/

drop synonym ALL_GEOMETRY_COLUMNS
/

drop synonym USER_GEOMETRY_COLUMNS
/

drop synonym OGIS_SPATIAL_REFERENCE_SYSTEMS
/

drop synonym SDO_CATALOG
/

drop synonym SDO_NN
/

drop synonym SDO_NN_DISTANCE
/

drop synonym SDO_FILTER
/

drop synonym SDO_RELATE
/

drop synonym SDO_RTREE_FILTER
/

drop synonym SDO_RTREE_RELATE
/

drop synonym SDO_WITHIN_DISTANCE
/

drop synonym LOCATOR_WITHIN_DISTANCE
/

drop synonym SDO_ANYINTERACT
/

drop synonym SDO_CONTAINS
/

drop synonym SDO_INSIDE
/

drop synonym SDO_TOUCH
/

drop synonym SDO_EQUAL
/

drop synonym SDO_COVERS
/

drop synonym SDO_ON
/

drop synonym SDO_COVEREDBY
/

drop synonym SDO_OVERLAPBDYDISJOINT
/

drop synonym SDO_OVERLAPBDYINTERSECT
/

drop synonym SDO_OVERLAPS
/

drop synonym SPATIAL_INDEX
/

drop synonym SPATIAL_INDEX_V2
/

drop synonym ST_GEOMETRY
/

drop synonym ST_POINT
/

drop synonym ST_CURVE
/

drop synonym ST_SURFACE
/

drop synonym ST_CURVEPOLYGON
/

drop synonym ST_LINESTRING
/

drop synonym ST_POLYGON
/

drop synonym ST_GEOMCOLLECTION
/

drop synonym ST_MULTIPOINT
/

drop synonym ST_MULTICURVE
/

drop synonym ST_MULTIFURFACE
/

drop synonym ST_MULTILINESTRING
/

drop synonym ST_MULTIPOLYGON
/

drop synonym ST_CIRCULARSTRING
/

drop synonym ST_COMPOUNDCURVE
/

drop synonym ST_GEOMETRY_ARRAY
/

drop synonym ST_POINT_ARRAY
/

drop synonym ST_CURVE_ARRAY
/

drop synonym ST_SURFACE_ARRAY
/

drop synonym ST_LINESTRING_ARRAY
/

drop synonym ST_POLYGON_ARRAY
/

drop synonym ST_INTERSECTS
/

drop synonym ST_RELATE
/

drop synonym ST_TOUCH
/

drop synonym ST_CONTAINS
/

drop synonym ST_COVERS
/

drop synonym ST_COVEREDBY
/

drop synonym ST_EQUAL
/

drop synonym ST_INSIDE
/

drop synonym ST_OVERLAPBDYDISJOINT
/

drop synonym ST_OVERLAPBDYINTERSECT
/

drop synonym ST_OVERLAPS
/

drop synonym MBRCOORDLIST
/

drop synonym SDO_STATISTICS
/

drop synonym SDO_MIGRATE
/

drop synonym SDO_PRIDX
/

drop synonym SDO_RTREE_ADMIN
/

drop synonym RTREEJOINFUNC
/

drop synonym SDO_TUNE
/

drop synonym HHNDIM
/

drop synonym HHLENGTH
/

drop synonym HHBYTELEN
/

drop synonym HHPRECISION
/

drop synonym HHLEVELS
/

drop synonym HHENCODE
/

drop synonym HHDECODE
/

drop synonym HHCELLBNDRY
/

drop synonym HHCELLSIZE
/

drop synonym HHSUBSTR
/

drop synonym HHCOLLAPSE
/

drop synonym HHCOMPOSE
/

drop synonym HHCOMMONCODE
/

drop synonym HHMATCH
/

drop synonym HHDISTANCE
/

drop synonym HHORDER
/

drop synonym HHGROUP
/

drop synonym HHJLDATE
/

drop synonym HHCLDATE
/

drop synonym HHIDPART
/

drop synonym HHIDLPART
/

drop synonym HHCOMPARE
/

drop synonym HHNCOMPARE
/

drop synonym HHSUBDIVIDE
/

drop synonym HHSTBIT
/

drop synonym HHGTBIT
/

drop synonym HHSTYPE
/

drop synonym HHGTYPE
/

drop synonym HHCBIT
/

drop synonym HHSBIT
/

drop synonym HHGBIT
/

drop synonym HHINCRLEV
/

drop synonym HHGETCID
/

drop synonym HHSETCID
/

drop synonym HHAND
/

drop synonym HHOR
/

drop synonym HHXOR
/

drop synonym HHENCODE_BYLEVEL
/

drop synonym HHMAXCODE
/

drop synonym USER_SDO_LIGHTSOURCES
/

drop synonym USER_SDO_ANIMATIONS
/

drop synonym USER_SDO_VIEWFRAMES
/

drop synonym USER_SDO_SCENES
/

drop synonym USER_SDO_3DTHEMES
/

drop synonym USER_SDO_3DTXFMS
/

drop synonym ALL_SDO_LIGHTSOURCES
/

drop synonym ALL_SDO_ANIMATIONS
/

drop synonym ALL_SDO_VIEWFRAMES
/

drop synonym ALL_SDO_SCENES
/

drop synonym ALL_SDO_3DTHEMES
/

drop synonym ALL_SDO_3DTXFMS
/

drop synonym USER_SDO_MAPS
/

drop synonym USER_SDO_STYLES
/

drop synonym USER_SDO_THEMES
/

drop synonym ALL_SDO_MAPS
/

drop synonym ALL_SDO_STYLES
/

drop synonym ALL_SDO_THEMES
/

drop synonym DBA_SDO_MAPS
/

drop synonym DBA_SDO_STYLES
/

drop synonym DBA_SDO_THEMES
/

drop synonym USER_SDO_CACHED_MAPS
/

drop synonym ALL_SDO_CACHED_MAPS
/

drop synonym POLYGONFROMTEXT
/

drop synonym LINESTRINGFROMTEXT
/

drop synonym MULTIPOLYGONFROMTEXT
/

drop synonym MULTILINESTRINGFROMTEXT
/

drop synonym POINTFROMTEXT
/

drop synonym POLYGONFROMWKB
/

drop synonym LINESTRINGFROMWKB
/

drop synonym MULTIPOLYGONFROMWKB
/

drop synonym MULTILINESTRINGFROMWKB
/

drop synonym POINTFROMWKB
/

drop synonym DIMENSION
/

drop synonym ASTEXT
/

drop synonym ASBINARY
/

drop synonym SRID
/

drop synonym OGC_X
/

drop synonym OGC_Y
/

drop synonym NUMINTERIORRINGS
/

drop synonym INTERIORRINGN
/

drop synonym EXTERIORRING
/

drop synonym NUMGEOMETRIES
/

drop synonym GEOMETRYN
/

drop synonym DISJOINT
/

drop synonym TOUCH
/

drop synonym WITHIN
/

drop synonym OVERLAP
/

drop synonym OGC_CONTAINS
/

drop synonym INTERSECTION
/

drop synonym DIFFERENCE
/

drop synonym OGC_UNION
/

drop synonym CONVEXHULL
/

drop synonym CENTROID
/

drop synonym GEOMETRYTYPE
/

drop synonym STARTPOINT
/

drop synonym ENDPOINT
/

drop synonym BOUNDARY
/

drop synonym ENVELOPE
/

drop synonym ISEMPTY
/

drop synonym NUMPOINTS
/

drop synonym POINTN
/

drop synonym ISCLOSED
/

drop synonym POINTONSURFACE
/

drop synonym AREA
/

drop synonym BUFFER
/

drop synonym EQUALS
/

drop synonym SYMMETRICDIFFERENCE
/

drop synonym DISTANCE
/

drop synonym OGC_LENGTH
/

drop synonym ISSIMPLE
/

drop synonym ISRING
/

drop synonym INTERSECTS
/

drop synonym RELATE
/

drop synonym CROSS
/

drop synonym MD_LRS
/

drop synonym SDO_LRS
/

drop synonym SDOAGGRTYPE
/

drop synonym SDO_AGGR_UNION
/

drop synonym SDO_AGGR_MBR
/

drop synonym SDO_AGGR_LRS_CONCAT
/

drop synonym SDO_AGGR_LRS_CONCAT_3D
/

drop synonym SDO_AGGR_CONVEXHULL
/

drop synonym SDO_AGGR_CENTROID
/

drop synonym SDO_AGGR_CONCAT_LINES
/

drop synonym SDO_AGGR_SET_UNION
/

drop synonym SDO_AGGR
/

drop synonym SDO_AGGR_CONCAVEHULL
/

drop synonym SDO_XML_SCHEMAS
/

drop synonym ST_ANNOTATIONTEXTELEMENT
/

drop synonym ST_ANNOT_TEXTELEMENT_ARRAY
/

drop synonym ST_ANNOTATIONTEXTELEMENT_ARRAY
/

drop synonym ST_ANNOTATION_TEXT
/

drop synonym USER_ANNOTATION_TEXT_METADATA
/

drop synonym ALL_ANNOTATION_TEXT_METADATA
/

drop synonym SDO_GEOM
/

drop synonym SDO_UTIL
/

drop synonym SDO_JOIN
/

drop synonym SDORIDTABLE
/

drop synonym SDO_GET_TAB_SUBPART
/

drop synonym SDO_GET_TAB_PART
/

drop synonym SDO_PQRY
/

drop synonym CIRCULARSTRING
/

drop synonym CURVE
/

drop synonym CURVEPOLYGON
/

drop synonym COMPOUNDCURVE
/

drop synonym GEOMETRYCOLLECTION
/

drop synonym GEOMETRY
/

drop synonym LINESTRING
/

drop synonym MULTICURVE
/

drop synonym MULTILINESTRING
/

drop synonym MULTIPOINT
/

drop synonym MULTIPOLYGON
/

drop synonym MULTISURFACE
/

drop synonym POINT
/

drop synonym POLYGON
/

drop synonym SURFACE
/

drop synonym CDB_AW_PROP
/

drop synonym CDB_AW_OBJ
/

drop synonym ALL_AW_AC
/

drop synonym ALL_OLAP2_AWS
/

drop synonym ALL_AW_AC_10G
/

drop synonym DBA_AW_PROP
/

drop synonym DBA_AW_OBJ
/

drop synonym USER_AW_PROP
/

drop synonym USER_AW_OBJ
/

drop synonym ALL_AW_PROP
/

drop synonym ALL_AW_OBJ
/

drop synonym ALL_AW_PROP_NAME
/

drop synonym DBMS_CUBE_ADVISE
/

drop synonym GENOLAPIEXCEPTION
/

drop synonym OLAPIHANDSHAKE2
/

drop synonym OLAPIBOOTSTRAP2
/

drop synonym GENINTERFACESTUB
/

drop synonym GENINTERFACESTUBSEQUENCE
/

drop synonym GENRAWSEQUENCE
/

drop synonym GENWSTRINGSEQUENCE
/

drop synonym SAM_SPARSITY_ADVICE
/

drop synonym DBMS_CUBE
/

drop synonym DBMS_CUBE_EXP
/

drop synonym GENDATABASEINTERFACE
/

drop synonym GENCONNECTIONINTERFACE
/

drop synonym GENSERVERINTERFACE
/

drop synonym GENMDMPROPERTYIDCONSTANTS
/

drop synonym GENMDMCLASSCONSTANTS
/

drop synonym GENMDMOBJECTIDCONSTANTS
/

drop synonym GENMETADATAPROVIDERINTERFACE
/

drop synonym GENCURSORMANAGERINTERFACE
/

drop synonym GENDATATYPEIDCONSTANTS
/

drop synonym GENDEFINITIONMANAGERINTERFACE
/

drop synonym GENDATAPROVIDERINTERFACE
/

drop synonym DBMS_AW_XML
/

drop synonym DBMS_CUBE_UTIL
/

drop synonym ALL_OLAP2_AW_CATALOGS
/

drop synonym ALL_OLAP2_AW_CATALOG_MEASURES
/

drop synonym ALL_OLAP2_AW_PHYS_OBJ
/

drop synonym ALL_OLAP2_AW_PHYS_OBJ_PROP
/

drop synonym ALL_OLAP2_AW_DIMENSIONS
/

drop synonym ALL_OLAP2_AW_ATTRIBUTES
/

drop synonym ALL_OLAP2_AW_CUBES
/

drop synonym ALL_OLAP2_AW_CUBE_DIM_USES
/

drop synonym ALL_AW_DIM_ENABLED_VIEWS
/

drop synonym ALL_AW_CUBE_ENABLED_VIEWS
/

drop synonym ALL_AW_CUBE_ENABLED_HIERCOMBO
/

drop synonym ALL_OLAP2_AW_DIM_LEVELS
/

drop synonym ALL_OLAP2_AW_DIM_HIER_LVL_ORD
/

drop synonym ALL_OLAP2_AW_CUBE_MEASURES
/

drop synonym ALL_OLAP2_AW_CUBE_AGG_SPECS
/

drop synonym ALL_OLAP2_AW_CUBE_AGG_MEAS
/

drop synonym ALL_OLAP2_AW_CUBE_AGG_LVL
/

drop synonym ALL_OLAP2_AW_CUBE_AGG_OP
/

drop synonym SDO_GEORASTER_ARRAY
/

drop synonym SDO_GEOR_HISTOGRAM_ARRAY
/

drop synonym SDO_OLS
/

drop synonym SDO_WFS_LOCK
/

drop synonym SDO_NETWORK_MANAGER_T
/

drop synonym SDO_NODE_T
/

drop synonym SDO_LINK_T
/

drop synonym SDO_PATH_T
/

drop synonym SDO_NETWORK_T
/

drop synonym TRACKER_MSG
/

drop synonym LOCATION_MSG
/

drop synonym LOCATION_MSG_ARR
/

drop synonym LOCATION_MSG_PKD
/

drop synonym PROC_MSG
/

drop synonym PROC_MSG_ARR
/

drop synonym PROC_MSG_PKD
/

drop synonym NOTIFICATION_MSG
/

drop synonym PRVT_SAM
/

drop synonym SDO_SAM
/

drop synonym SDO_GCDR
/

drop synonym SDO_WFS_PROCESS
/

drop synonym USER_SDO_CSW_SERVICE_INFO
/

drop synonym ALL_SDO_CSW_SERVICE_INFO
/

drop synonym SDO_CSW
/

drop synonym SDO_POINTINPOLYGON
/

drop synonym SDO_TRKR
/

drop synonym SDO_TOPO_MAP
/

drop synonym SDO_TOPO
/

drop synonym SDO_TOPO_ANYINTERACT
/

drop synonym SDO_GEOR_METADATA
/

drop synonym SDO_RASTER
/

drop synonym SDO_RASTERSET
/

drop synonym SDO_GEOR_SRS
/

drop synonym SDO_GEOR_HISTOGRAM
/

drop synonym SDO_GEOR_GRAYSCALE
/

drop synonym SDO_GEOR_COLORMAP
/

drop synonym SDO_GEOR_GCP
/

drop synonym SDO_GEOR_GCP_COLLECTION
/

drop synonym SDO_GEOR_GCPGEOREFTYPE
/

drop synonym SDO_GEOR_CELL
/

drop synonym SDO_GEOR_CELL_TABLE
/

drop synonym USER_SDO_GEOR_SYSDATA
/

drop synonym ALL_SDO_GEOR_SYSDATA
/

drop synonym SDO_GEORASTER
/

drop synonym SDO_GEOR
/

drop synonym SDO_GEOR_AUX
/

drop synonym SDO_GEOR_ADMIN
/

drop synonym SDO_GEOR_UTL
/

drop synonym SDO_GEOR_RA
/

drop synonym SDO_GEOR_AGGR
/

drop synonym SDO_GEOR_IP
/

drop synonym SDO_GEOR_GDAL
/

drop synonym SDO_ORGSCL_TYPE
/

drop synonym SDO_PC_BLK
/

drop synonym SDO_PC
/

drop synonym SDO_TIN_BLK
/

drop synonym SDO_TIN
/

drop synonym ALL_SDO_TIN_PC_SYSDATA
/

drop synonym USER_SDO_TIN_PC_SYSDATA
/

drop synonym SDO_PC_PKG
/

drop synonym SDO_LODS_TYPE
/

drop synonym SDO_TIN_PKG
/

drop synonym SDO_WCS
/

drop synonym USER_SDO_NETWORK_METADATA
/

drop synonym ALL_SDO_NETWORK_METADATA
/

drop synonym USER_SDO_NETWORK_CONSTRAINTS
/

drop synonym ALL_SDO_NETWORK_CONSTRAINTS
/

drop synonym USER_SDO_NETWORK_JAVA_OBJECTS
/

drop synonym ALL_SDO_NETWORK_JAVA_OBJECTS
/

drop synonym USER_SDO_NETWORK_LOCKS_WM
/

drop synonym ALL_SDO_NETWORK_LOCKS_WM
/

drop synonym USER_SDO_NETWORK_USER_DATA
/

drop synonym ALL_SDO_NETWORK_USER_DATA
/

drop synonym USER_SDO_NETWORK_HISTORIES
/

drop synonym ALL_SDO_NETWORK_HISTORIES
/

drop synonym USER_SDO_NETWORK_TIMESTAMPS
/

drop synonym ALL_SDO_NETWORK_TIMESTAMPS
/

drop synonym SDO_NET_UPD_HIST
/

drop synonym SDO_NET_UPD_HIST_TBL
/

drop synonym SDO_NET_UPD_HIST_N
/

drop synonym SDO_NET_UPD_HIST_NTBL
/

drop synonym SDO_NET_LINK
/

drop synonym SDO_NET_LINK_NTBL
/

drop synonym SDO_NET_OP
/

drop synonym SDO_NET_OP_NTBL
/

drop synonym SDO_NET_FEAT_ELEM
/

drop synonym SDO_NET_FEAT_ELEM_ARRAY
/

drop synonym SDO_NET_LAYER_FEAT
/

drop synonym SDO_NET_LAYER_FEAT_ARRAY
/

drop synonym USER_SDO_NETWORK_FEATURE
/

drop synonym ALL_SDO_NETWORK_FEATURE
/

drop synonym SDO_NET_PARTITION
/

drop synonym SDO_NET
/

drop synonym SDO_NET_MEM
/

drop synonym SDO_ROUTER_PARTITION
/

drop synonym ELOCATION_EDGE_LINK_LEVEL
/

drop synonym SDO_ROUTER_TIMEZONE
/

drop synonym SDO_NDM_TRAFFIC
/

drop synonym USER_SDO_NFE_MODEL_METADATA
/

drop synonym ALL_SDO_NFE_MODEL_METADATA
/

drop synonym USER_SDO_NFE_MODEL_FTLAYER_REL
/

drop synonym ALL_SDO_NFE_MODEL_FTLAYER_REL
/

drop synonym USER_SDO_NFE_MODEL_WORKSPACE
/

drop synonym ALL_SDO_NFE_MODEL_WORKSPACE
/

drop synonym SDO_INTERACT_POINT_FEAT
/

drop synonym SDO_INTERACT_POINT_FEAT_ARRAY
/

drop synonym SDO_INTERACT_LINE_FEAT
/

drop synonym SDO_INTERACT_LINE_FEAT_ARRAY
/

drop synonym SDO_INTERACTION
/

drop synonym SDO_INTERACTION_ARRAY
/

drop synonym SDO_NFE
/

drop synonym SDO_RDF_TERM
/

drop synonym SDO_RDF_TRIPLE
/

drop synonym SDO_RDF_TRIPLE_S
/

drop synonym SDO_RDF_ROWTYPE
/

drop synonym SDO_RDF_TERM_LIST
/

drop synonym RDFSA_RESOURCE
/

drop synonym SDO_RDF_MODELS
/

drop synonym SDO_RDF_RULEBASES
/

drop synonym SDO_RDF_ALIAS
/

drop synonym SDO_RDF_ALIASES
/

drop synonym SDO_RDF_GRAPHS
/

drop synonym SDO_RDF_CLOBS
/

drop synonym SDO_RDF_ENTAILMENTS
/

drop synonym SEM_MODELS
/

drop synonym SEM_RULEBASES
/

drop synonym SEM_ALIAS
/

drop synonym SEM_ALIASES
/

drop synonym SEM_VARCHARARRAY
/

drop synonym SEM_LONGVARCHARARRAY
/

drop synonym SEM_GRAPHS
/

drop synonym SEM_CLOBS
/

drop synonym SEM_ENTAILMENTS
/

drop synonym SEM_APIS_GROUP_CONCAT
/

drop synonym SEM_APIS_SAMPLE
/

drop synonym SEM_APIS_MIN
/

drop synonym SEM_APIS_MAX
/

drop synonym SEM_APIS_GROUP_CONCAT_VC
/

drop synonym SEM_APIS_SAMPLE_VC
/

drop synonym SEM_APIS_MIN_VC
/

drop synonym SEM_APIS_MAX_VC
/

drop synonym SDO_SEM_INFERENCE
/

drop synonym SDO_SEM_VALIDATE
/

drop synonym SDO_RDF_INFERENCE
/

drop synonym SEM_APIS
/

drop synonym SDO_RDF_MATCH
/

drop synonym SEM_MATCH
/

drop synonym SPARQL_SERVICE
/

drop synonym SEM_MATCH_NL
/

drop synonym SDO_RDF_INTERNAL
/

drop synonym SEM_PERF
/

drop synonym SDO_RDF
/

drop synonym SDO_SEM
/

drop synonym SEM_RELATED
/

drop synonym SEM_DISTANCE
/

drop synonym SEM_UPGRADE_TO_11
/

drop synonym SDO_SEM_DOWNGRADE
/

drop synonym SDO_SEM_DOWNGRADE_UTL
/

drop synonym SEM_RDFCTX
/

drop synonym SEM_CONTAINS
/

drop synonym SEM_CONTAINS_SELECT
/

drop synonym SEM_CONTAINS_COUNT
/

drop synonym SEM_OLS
/

drop synonym SEM_RDFSA
/

drop synonym OPG_APIS
/

drop synonym OPG_PATH
/

drop synonym OPG_RANK
/

drop synonym OPG_METRICS
/

drop synonym OPG_GRAPHOP
/

drop synonym NUMERIC_TO_LBAC
/

drop synonym LBAC_TO_NUMERIC
/

drop synonym TO_LABEL_LIST
/

drop synonym PRIVS_TO_CHAR
/

drop synonym PRIVS_TO_CHAR_N
/

drop synonym OID_ENABLED
/

drop synonym LBAC_UTL
/

drop synonym LBAC_SESSION
/

drop synonym SA_AUDIT_ADMIN
/

drop synonym ORA_GET_AUDITED_LABEL
/

drop synonym LBAC_POLICY_ADMIN
/

drop synonym SA_SYSDBA
/

drop synonym SA_POLICY_ADMIN
/

drop synonym TO_NUMERIC_LABEL
/

drop synonym LABEL_TO_CHAR
/

drop synonym NUMERIC_LABEL_TO_CHAR
/

drop synonym TO_LBAC_DATA_LABEL
/

drop synonym TO_LBAC_LABEL
/

drop synonym LBAC_LABEL_TO_CHAR
/

drop synonym TO_NUMERIC_DATA_LABEL
/

drop synonym SA_LABEL_ADMIN
/

drop synonym SA_COMPONENTS
/

drop synonym SA_SESSION
/

drop synonym SA_UTL
/

drop synonym SA_USER_ADMIN
/

drop synonym CDB_LBAC_POLICIES
/

drop synonym CDB_LBAC_SCHEMA_POLICIES
/

drop synonym CDB_LBAC_TABLE_POLICIES
/

drop synonym DBA_LBAC_POLICIES
/

drop synonym DBA_LBAC_SCHEMA_POLICIES
/

drop synonym DBA_LBAC_TABLE_POLICIES
/

drop synonym CDB_SA_POLICIES
/

drop synonym CDB_SA_SCHEMA_POLICIES
/

drop synonym CDB_SA_TABLE_POLICIES
/

drop synonym CDB_SA_LABELS
/

drop synonym CDB_SA_DATA_LABELS
/

drop synonym CDB_SA_LEVELS
/

drop synonym CDB_SA_COMPARTMENTS
/

drop synonym CDB_SA_GROUPS
/

drop synonym CDB_SA_GROUP_HIERARCHY
/

drop synonym CDB_SA_USER_LEVELS
/

drop synonym CDB_SA_USER_COMPARTMENTS
/

drop synonym CDB_SA_USER_GROUPS
/

drop synonym CDB_SA_USERS
/

drop synonym CDB_SA_USER_LABELS
/

drop synonym CDB_SA_USER_PRIVS
/

drop synonym CDB_SA_PROGRAMS
/

drop synonym CDB_SA_PROG_PRIVS
/

drop synonym DBA_SA_POLICIES
/

drop synonym DBA_SA_TABLE_POLICIES
/

drop synonym DBA_SA_SCHEMA_POLICIES
/

drop synonym DBA_SA_LABELS
/

drop synonym DBA_SA_DATA_LABELS
/

drop synonym DBA_SA_LEVELS
/

drop synonym DBA_SA_COMPARTMENTS
/

drop synonym DBA_SA_GROUPS
/

drop synonym DBA_SA_GROUP_HIERARCHY
/

drop synonym DBA_SA_USERS
/

drop synonym DBA_SA_USER_LEVELS
/

drop synonym DBA_SA_USER_COMPARTMENTS
/

drop synonym DBA_SA_USER_GROUPS
/

drop synonym DBA_SA_USER_LABELS
/

drop synonym DBA_SA_USER_PRIVS
/

drop synonym DBA_SA_PROGRAMS
/

drop synonym DBA_SA_PROG_PRIVS
/

drop synonym ALL_SA_POLICIES
/

drop synonym ALL_SA_TABLE_POLICIES
/

drop synonym ALL_SA_SCHEMA_POLICIES
/

drop synonym ALL_SA_LABELS
/

drop synonym ALL_SA_DATA_LABELS
/

drop synonym ALL_SA_LEVELS
/

drop synonym ALL_SA_COMPARTMENTS
/

drop synonym ALL_SA_GROUPS
/

drop synonym ALL_SA_GROUP_HIERARCHY
/

drop synonym ALL_SA_USERS
/

drop synonym ALL_SA_USER_LEVELS
/

drop synonym ALL_SA_USER_COMPARTMENTS
/

drop synonym ALL_SA_USER_GROUPS
/

drop synonym ALL_SA_USER_LABELS
/

drop synonym ALL_SA_USER_PRIVS
/

drop synonym ALL_SA_PROG_PRIVS
/

drop synonym USER_SA_SESSION
/

drop synonym CDB_SA_AUDIT_OPTIONS
/

drop synonym CDB_OLS_STATUS
/

drop synonym LBAC_AUDIT_ACTIONS
/

drop synonym DBA_SA_AUDIT_OPTIONS
/

drop synonym ALL_SA_AUDIT_OPTIONS
/

drop synonym DBA_OLS_STATUS
/

drop synonym TO_DATA_LABEL
/

drop synonym CHAR_TO_LABEL
/

drop synonym TAGSEQ_TO_CHAR
/

drop synonym DOMINATES
/

drop synonym STRICTLY_DOMINATES
/

drop synonym DOMINATED_BY
/

drop synonym STRICTLY_DOMINATED_BY
/

drop synonym LEAST_UBOUND
/

drop synonym MERGE_LABEL
/

drop synonym GREATEST_LBOUND
/

drop synonym DOM
/

drop synonym S_DOM
/

drop synonym DOM_BY
/

drop synonym S_DOM_BY
/

drop synonym LUBD
/

drop synonym GLBD
/

drop synonym OLS_DOMINATES
/

drop synonym OLS_STRICTLY_DOMINATES
/

drop synonym OLS_DOMINATED_BY
/

drop synonym OLS_STRICTLY_DOMINATED_BY
/

drop synonym OLS_DOM
/

drop synonym OLS_S_DOM
/

drop synonym OLS_DOM_BY
/

drop synonym OLS_S_DOM_BY
/

drop synonym OLS_LEAST_UBOUND
/

drop synonym OLS_GREATEST_LBOUND
/

drop synonym OLS_LUBD
/

drop synonym OLS_GLBD
/

drop synonym OLS_LABEL_DOMINATES
/

drop synonym LDAP_ATTR
/

drop synonym LDAP_ATTR_LIST
/

drop synonym LDAP_EVENT
/

drop synonym LDAP_EVENT_STATUS
/

drop synonym OLS_DIP_NTFY
/

drop synonym PLSQL_STACK_ARRAY
/

drop synonym SIMULATION_IDS
/

drop synonym DV_OBJ_NAME
/

drop synonym DBMS_MACADM
/

drop synonym DBMS_MACSEC_ROLES
/

drop synonym DBMS_MACUTL
/

drop synonym DBMS_MACOLS_SESSION
/

drop synonym GET_FACTOR
/

drop synonym GET_FACTOR_LABEL
/

drop synonym SET_FACTOR
/

drop synonym GET_TRUST_LEVEL
/

drop synonym GET_TRUST_LEVEL_FOR_IDENTITY
/

drop synonym ROLE_IS_ENABLED
/

drop synonym IS_SECURE_APPLICATION_ROLE
/

drop synonym DV_DATABASE_NAME
/

drop synonym DV_DICT_OBJ_NAME
/

drop synonym DV_DICT_OBJ_OWNER
/

drop synonym DV_DICT_OBJ_TYPE
/

drop synonym DV_INSTANCE_NUM
/

drop synonym DV_JOB_INVOKER
/

drop synonym DV_JOB_OWNER
/

drop synonym DV_LOGIN_USER
/

drop synonym DV_SQL_TEXT
/

drop synonym DV_SYSEVENT
/

drop synonym DBA_DV_AUTH
/

drop synonym DBA_DV_CODE
/

drop synonym DBA_DV_COMMAND_RULE
/

drop synonym DBA_DV_COMMAND_RULE_ID
/

drop synonym DBA_DV_DATAPUMP_AUTH
/

drop synonym DBA_DV_DDL_AUTH
/

drop synonym DBA_DV_DEBUG_CONNECT_AUTH
/

drop synonym DBA_DV_DIAGNOSTIC_AUTH
/

drop synonym DBA_DV_DICTIONARY_ACCTS
/

drop synonym DBA_DV_FACTOR
/

drop synonym DBA_DV_FACTOR_LINK
/

drop synonym DBA_DV_FACTOR_TYPE
/

drop synonym DBA_DV_IDENTITY
/

drop synonym DBA_DV_IDENTITY_MAP
/

drop synonym DBA_DV_JOB_AUTH
/

drop synonym DBA_DV_MAC_POLICY
/

drop synonym DBA_DV_MAC_POLICY_FACTOR
/

drop synonym DBA_DV_MAINTENANCE_AUTH
/

drop synonym DBA_DV_ORADEBUG
/

drop synonym DBA_DV_PATCH_ADMIN_AUDIT
/

drop synonym DBA_DV_POLICY
/

drop synonym DBA_DV_POLICY_LABEL
/

drop synonym DBA_DV_POLICY_OBJECT
/

drop synonym DBA_DV_POLICY_OWNER
/

drop synonym DBA_DV_PREPROCESSOR_AUTH
/

drop synonym DBA_DV_PROXY_AUTH
/

drop synonym DBA_DV_PUB_PRIVS
/

drop synonym DBA_DV_REALM
/

drop synonym DBA_DV_REALM_AUTH
/

drop synonym DBA_DV_REALM_OBJECT
/

drop synonym DBA_DV_ROLE
/

drop synonym DBA_DV_RULE
/

drop synonym DBA_DV_RULE_SET
/

drop synonym DBA_DV_RULE_SET_RULE
/

drop synonym DBA_DV_SIMULATION_LOG
/

drop synonym DBA_DV_TTS_AUTH
/

drop synonym DBA_DV_USER_PRIVS
/

drop synonym DBA_DV_USER_PRIVS_ALL
/

drop synonym DV_ADMIN_GRANTEES
/

drop synonym DV_AUDIT_CLEANUP_GRANTEES
/

drop synonym DV_MONITOR_GRANTEES
/

drop synonym DV_OWNER_GRANTEES
/

drop synonym DV_SECANALYST_GRANTEES
/

drop synonym DBA_DV_DBCAPTURE_AUTH
/

drop synonym DBA_DV_DBREPLAY_AUTH
/

drop synonym DBA_DV_APP_EXCEPTION
/

drop synonym CONFIGURE_DV
/

drop synonym CDB_DV_STATUS
/

drop synonym DBA_DV_STATUS
/

drop synonym DBMS_CLR
/

