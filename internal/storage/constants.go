package storage

const (
	SecretNameBase = "tfa-claims-"
	ClaimsLabel    = "traefik-forward-auth/claim"
	ClaimsIDLabel  = "traefik-forward-auth/claim-id"
	UserInfoKey    = "userInfo"
	ClaimsIdCookie = "_tfa_claims_id"
	ClaimsIdLength = 24
)
