keys_path = test-image/nginx/keys

test/keys:
	@mkdir $(keys_path)
	@openssl genrsa 2048 > $(keys_path)/rsa-private.pem
	@openssl genrsa 2048 > $(keys_path)/rsa-wrong-private.pem
	@openssl rsa -in $(keys_path)/rsa-private.pem -pubout > $(keys_path)/rsa-public.pem
	@openssl rsa -in $(keys_path)/rsa-wrong-private.pem -pubout > $(keys_path)/rsa-wrong-public.pem

clear:
	@rm -r $(keys_path)
