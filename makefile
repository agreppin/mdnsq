COPTS	:= -O0
#FFLAGS	:= -fsanitize=address
CFLAGS	:= -g3 $(COPTS) -Wall -Wextra $(FFLAGS)
CPPFLAGS:= -D_DEFAULT_SOURCE
LDFLAGS	:= -g3

all: mdnsq

mdnsq: mdnsq.c

# https://appsec.guide/docs/fuzzing/c-cpp/techniques/coverage-analysis/
# https://github.com/google/fuzzing/issues/41
fuzzer_CFLAGS := $(CFLAGS) -fsanitize=fuzzer,address
fuzzer_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
fuzzer: mdnsq.c
	clang -g3 $(fuzzer_CFLAGS) -DFUZZ=1 -o $@ mdnsq.c
fuzz-help: fuzzer
	./fuzzer -help=1
fuzz: fuzzer corpus
	LLVM_PROFILE_FILE=fuzz.profraw \
	./fuzzer -max_len=1500 -runs=999999 corpus
fuzz.profraw: fuzzer corpus
	LLVM_PROFILE_FILE=fuzz.profraw \
	./fuzzer -max_len=1500 -runs=0 corpus
fuzz.profdata: fuzz.profraw
	llvm-profdata merge -sparse fuzz.profraw -o $@
fuzz-coverage-report: fuzz.profdata
	llvm-cov report ./fuzzer -instr-profile=fuzz.profdata
fuzz-coverage-show:   fuzz.profdata
	llvm-cov show   ./fuzzer -instr-profile=fuzz.profdata
corpus:
	cp -a corpus_ref corpus
clean:
	rm -f *.o fuzz* mdnsq
clobber: clean
	rm -rf corpus
diet:
	rm -f mdnsq
	$(MAKE) CC='diet -Os gcc' COPTS='-Os' mdnsq

.PHONY: all clean clobber diet fuzz fuzz-coverage-report fuzz-coverage-show