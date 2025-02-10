package auth

// Permissions is a full model for all available permissions
type Permissions struct {
	User  UserPermissions  `json:"user"`
	Bot   BotPermissions   `json:"bot"`
	Admin AdminPermissions `json:"admin"`
}

type UserPermissions struct {
	Login bool `json:"login,omitempty"`
}

type AdminPermissions struct {
	Login bool `json:"login,omitempty"`
}

type BotPermissions struct {
	Connection bool `json:"connection,omitempty"`
}
