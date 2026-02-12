PYTHON=python3

all: bchoc

bchoc: main.py
	echo '#!/usr/bin/env $(PYTHON)' > bchoc
	echo 'import sys' >> bchoc
	echo 'from main import cli_main' >> bchoc
	echo 'sys.exit(cli_main())' >> bchoc
	chmod +x bchoc

clean:
	rm -f bchoc