package storage

const (
	SecretNameBase = "tfa-claims-"
	ClaimsLabel    = "oauth-middleware/claim"
	ClaimsIDLabel  = "oauth-middleware/claim-id"
	UserInfoKey    = "userInfo"
	ClaimsIdCookie = "_tfa_claims_id"
	ClaimsIdLength = 24
)
