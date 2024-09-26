
# Deploying on Kubernetes and using GCP OAuth 2.0 Client ID

This example shows a kubernetes deployment and service to running a traefik-forward-auth container. It assumes the namespace is traefik. If you are not using this namespace then change it to suit your environment.

1. The traefik forward auth deployment. You will need to supply the following environment variables

| Envronment Variable name  | Value  | Description    |
| :---------------------:   | :---:  | :---:          |
| CLIENT_ID                 | Your GCP Credential ID | Get this from Oauth 2.0 Credential  https://console.cloud.google.com/apis/credentials |
| CLIENT_SECRET             | Your GCP Credential Secret | See Above |
| DOMAIN | The E-mail addresses of the GCP accounts | A comma seperated list of e-mails domains |
| PROVIDER_URI | https://accounts.google.com | This is the same URL for all deployments |
| SCOPE | openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile | A space seperated string;  you can use the example supplied as is as this always the same across deployments |
| SECRET | A-random-secret | A Random secret string |
| ENCRYPTION_KEY | RANDOM-STRING-MINIMUM-OF-16-CHARS-LONG | An AES compatible string which should either be 16, 24, or 32 Bytes long |

The following deployment will create a traefik forward auth container.

```
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: traefik-forward-auth
  name: traefik-forward-auth
  namespace: traefik
spec:
  replicas: 1
  selector:
    matchLabels:
      app: traefik-forward-auth
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: traefik-forward-auth
    spec:
      containers:
      - env:
        - name: DOMAIN
          value: myemaildomain.com,myotheremaildomain.org
        - name: CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: traefik-forward-auth-secrets
              key: client-id
        - name: CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: traefik-forward-auth-secrets
              key: client-secret
        - name: PROVIDER_URI
          value: https://accounts.google.com
        - name: SCOPE
          value: openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
        - name: SECRET
          valueFrom:
            secretKeyRef:
              name: traefik-forward-auth-secrets
              key: secret
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: traefik-forward-auth-secrets
              key: encryption-key
        - name: LOG_LEVEL
          value: debug
        image: mesosphere/traefik-forward-auth:latest
        imagePullPolicy: Always
        name: traefik-forward-auth
        ports:
        - containerPort: 4181
          protocol: TCP
        resources: {}
```

2. The kubernetes service.

This service provides the consistent endpoint for Traefik Middleware to send auth requests to.

```
apiVersion: v1
kind: Service
metadata:
  labels:
    app: traefik-forward-auth
  name: traefik-forward-auth
  namespace: traefik
spec:
  ports:
  - name: auth-http
    port: 4181
    protocol: TCP
    targetPort: 4181
  selector:
    app: traefik-forward-auth
  sessionAffinity: None
  type: ClusterIP
```

3. The Traefik Middleware.  This makes the Traefik Middleware available for traefik routes.

```
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: auth-only-ovo
  namespace: traefik
spec:
  forwardAuth:
    address: http://traefik-forward-auth:4181
    authResponseHeaders:
    - X-Forwarded-User
    trustForwardHeader: true
```
