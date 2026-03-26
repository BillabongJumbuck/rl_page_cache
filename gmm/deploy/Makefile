all:
	uv run export_model.py
	gcc -O3 cml_agent.c -o cml_agent.out -lbpf -lm

clean:
	rm -f cml_agent.out gmm_weights.h