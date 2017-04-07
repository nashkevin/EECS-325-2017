
make:
	gcc PacketTrace.c -Wall -Werror -g -o proj3

clean:
	rm -f *.o

test:
	gcc PacketTrace.c -g -o proj3
	./proj3 -r sample-A.dmp -p > testA-p.out
	./proj3 -r sample-B.dmp -p > testB-p.out
	./proj3 -r sample-C.dmp -p > testC-p.out
	./proj3 -r sample-E.dmp -p > testE-p.out
	./proj3 -r sample-H.dmp -p > testH-p.out
	diff sample-A-p.out testA-p.out
	diff sample-B-p.out testB-p.out
	diff sample-C-p.out testC-p.out
	diff sample-E-p.out testE-p.out
	diff sample-H-p.out testH-p.out

stress:
	gcc PacketTrace.c -g -o proj3
	./proj3 -r sample-I.dmp -p > testI-p.out
