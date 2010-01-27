all:    static_library client_tester server_tester

static_library: 
	g++ -c ssl_wrapper.c -o ssl_wrapper.o -I/usr/include/openssl -lssl
	ar rcs libsslwrapper.a ssl_wrapper.o 

client_tester:  
	g++ -L"." -o client_tester client_tester.c -lsslwrapper -I/usr/include/openssl -lssl

server_tester:  
	g++ -L"." -o server_tester server_tester.c -lsslwrapper -I/usr/include/openssl -lssl

clean:
	rm -rf client_tester server_tester *.o *.so *.a
