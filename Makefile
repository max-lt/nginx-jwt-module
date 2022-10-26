keys_path = test-image/nginx/keys

test/keys:
	@mkdir -p $(keys_path)
	@openssl genrsa 2048 > $(keys_path)/rsa-private.pem
	@openssl genrsa 2048 > $(keys_path)/rsa-wrong-private.pem
	@openssl rsa -in $(keys_path)/rsa-private.pem -pubout > $(keys_path)/rsa-public.pem
	@openssl rsa -in $(keys_path)/rsa-wrong-private.pem -pubout > $(keys_path)/rsa-wrong-public.pem

# Tests with an existing container
# usage: make test/current container=my-test-container
#   same as ./test.sh --current my-test-container
# example:
#   terminal 1: docker run --rm --name my-test-container -p 8000:8000 jwt-nginx-test
#   terminal 2: make test/current container=my-test-container
test/current:
	@bash test.sh --current $(container)

# Tests with a given image
# usage: make test/image image=my-test-image
#   same as ./test.sh your-image-to-test
test/image:
	@bash test.sh $(image)

# Used by Github workflow
test/local:
	@bash test.sh --local

# Build test image & run test suite
test: test/keys
	@bash test.sh

clear:
	@rm -r $(keys_path)
