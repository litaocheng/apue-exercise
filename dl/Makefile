all: test_so
	gcc  -rdynamic main.c -o testdl -ldl
	
test_so: test.c
	gcc -shared -fPIC -o libtestdl.so $<

clean:
	rm -rf *.so
	rm -rf testdl
