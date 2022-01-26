data := data/
challenge_data_url := https://cryptopals.com/static/challenge-data/

test-data:
	test -d data || mkdir -p data/set01;  
	for problem_set in 01; do \
		for challenge in 4 6 7 8; do \
			test -f ${data}/set$${problem_set}/$${challenge}.txt || curl -o ${data}/set$${problem_set}/$${challenge}.txt https://cryptopals.com/static/challenge-data/$$challenge.txt; \
		done \
	done
test: test-data
	cargo test

