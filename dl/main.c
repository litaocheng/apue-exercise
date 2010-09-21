#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>


int a = 3;
int main(int argc, char * argv[])
{
    void * handle;
    int (*fn)(int b);
    char * error;
    int n;

    /* load the dll */
    if ((handle = dlopen("./libtestdl.so", RTLD_LAZY|RTLD_DEEPBIND|RTLD_GLOBAL)) == NULL) {
        fprintf(stderr, "open the dll error:%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();

    fn = dlsym(handle, "fun");
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    n = fn(3);
    printf("fun return:%d\n", n);
    dlclose(handle);
    exit(EXIT_SUCCESS);
}
