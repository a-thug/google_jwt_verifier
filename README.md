# google_jwt_verifier
futurenda/google-auth-id-token-verifier without depending on golang.org/x/oauth2/jws

# overview
[futurenda/google-auth-id-token-verifier](https://github.com/futurenda/google-auth-id-token-verifier) is depends on [jws.go](https://github.com/golang/oauth2/blob/master/jws/jws.go) although jws.go will be removed in future.
So based on google-auth-id-token-verifier, add jws.go's struct and function.

# sample
```
bearerToken := req.Header.Get("Authorization")
if bearerToken == "" {
	log.Printf("Token must exist")
	return
}
token := strings.Split(bearerToken, " ")[1]
aud := "xxxxxx-yyyyyyy.apps.googleusercontent.com"
err := googleJWTVerifier.VerifyIDToken(token, []string{
    aud,
})
if err != nil {
	log.Printf("Auth error: %v", err)
	return
}
```

# main purpose
If you use Google Cloud Pub/Sub and Google Cloud Run on GKE, you must validate Pub/Sub JWT.
Please　use this library in such a case.

# ref
https://github.com/futurenda/google-auth-id-token-verifier
https://github.com/golang/oauth2/blob/master/jws/jws.go
https://cloud.google.com/run/docs/tutorials/pubsub
https://developers.google.com/identity/protocols/OpenIDConnect?_ga=2.157273531.-1681326071.1575298365#validatinganidtoken

