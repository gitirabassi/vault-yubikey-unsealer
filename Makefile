
start:
	vault server -config=test-vault.hcl

init:
	vault operator init -address=http://127.0.0.1:8200  -key-threshold=3 -key-shares=5 -format=json

status:
	vault status -address=http://127.0.0.1:8200

