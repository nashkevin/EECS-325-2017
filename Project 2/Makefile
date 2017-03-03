
make:
	gcc PacketTrace.c -Wall -Werror -g -o proj2

clean:
	rm -f *.o

test:
	gcc PacketTrace.c -g -o proj2
	./proj2 -r sample-A1.dmp -s > testA1-s.out
	./proj2 -r sample-A2.dmp -s > testA2-s.out
	./proj2 -r sample-A3.dmp -s > testA3-s.out
	./proj2 -r sample-B.dmp -s > testB-s.out
	./proj2 -r sample-C.dmp -s > testC-s.out
	./proj2 -r sample-D.dmp -s > testD-s.out
	./proj2 -r sample-A1.dmp -e > testA1-e.out
	./proj2 -r sample-A2.dmp -e > testA2-e.out
	./proj2 -r sample-A3.dmp -e > testA3-e.out
	./proj2 -r sample-B.dmp -e > testB-e.out
	./proj2 -r sample-A1.dmp -i > testA1-i.out
	./proj2 -r sample-A2.dmp -i > testA2-i.out
	./proj2 -r sample-A3.dmp -i > testA3-i.out
	./proj2 -r sample-B.dmp -i > testB-i.out
	./proj2 -r sample-A1.dmp -t > testA1-t.out
	./proj2 -r sample-A2.dmp -t > testA2-t.out
	./proj2 -r sample-A3.dmp -t > testA3-t.out
	./proj2 -r sample-E.dmp -t > testE-t.out
	./proj2 -r sample-F1.dmp -t > testF1-t.out
	./proj2 -r sample-F2.dmp -t > testF2-t.out
	diff sample-A1-s.out testA1-s.out
	diff sample-A2-s.out testA2-s.out
	diff sample-A3-s.out testA3-s.out
	diff sample-B-s.out testB-s.out
	diff sample-C-s.out testC-s.out
	diff sample-D-s.out testD-s.out
	diff sample-A1-e.out testA1-e.out
	diff sample-A2-e.out testA2-e.out
	diff sample-A3-e.out testA3-e.out
	diff sample-B-e.out testB-e.out
	diff sample-A1-i.out testA1-i.out
	diff sample-A2-i.out testA2-i.out
	diff sample-A3-i.out testA3-i.out
	diff sample-B-i.out testB-i.out
	diff sample-A1-t.out testA1-t.out
	diff sample-A2-t.out testA2-t.out
	diff sample-A3-t.out testA3-t.out
	diff sample-E-t.out testE-t.out
	diff sample-F1-t.out testF1-t.out
	diff sample-F2-t.out testF2-t.out
