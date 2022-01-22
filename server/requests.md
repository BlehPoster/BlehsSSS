# Requests
Every request (except ECDH Init) is encrypted using the shared secret between client and server
````
Request:
{
	"id": <id>,
	"ct": <ct of content using e key>
}
````
## Public
### ECDH Init
## Admin
### create account

````
Content:
{
	"ed25519_proof": <proof>,
	"content": {
		"new_user_id_pub_key": <public id key>,
		"new_user_e_pub_key": <public e key>,
		"user_nickname": <nickname>,
	}
}
````
## User
### Request User Data
### Provide own Share

## Super User
### Request Secret from provided Shares