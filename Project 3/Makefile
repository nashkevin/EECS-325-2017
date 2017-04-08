
make:
	gcc PacketTrace.c -Wall -Werror -g -o proj3

clean:
	rm -f *.o

test:
	gcc PacketTrace.c -g -o proj3
	# TESTING PACKET DUMPS
	./proj3 -r sample-A.dmp -p > testA-p.out
	./proj3 -r sample-B.dmp -p > testB-p.out
	./proj3 -r sample-C.dmp -p > testC-p.out
	./proj3 -r sample-D.dmp -p > testD-p.out
	./proj3 -r sample-E.dmp -p > testE-p.out
	./proj3 -r sample-F1.dmp -p > testF1-p.out
	./proj3 -r sample-F2.dmp -p > testF2-p.out
	./proj3 -r sample-F3.dmp -p > testF3-p.out
	./proj3 -r sample-H.dmp -p > testH-p.out
	diff sample-A-p.out testA-p.out
	diff sample-B-p.out testB-p.out
	diff sample-C-p.out testC-p.out
	diff sample-E-p.out testE-p.out
	diff sample-H-p.out testH-p.out
	# TESTING CONNECTION SUMMARIES
	./proj3 -r sample-A.dmp -s > testA-s.out
	./proj3 -r sample-B.dmp -s > testB-s.out
	./proj3 -r sample-C.dmp -s > testC-s.out
	./proj3 -r sample-D.dmp -s > testD-s.out
	./proj3 -r sample-E.dmp -s > testE-s.out
	./proj3 -r sample-F1.dmp -s > testF1-s.out
	./proj3 -r sample-F2.dmp -s > testF2-s.out
	./proj3 -r sample-F3.dmp -s > testF3-s.out
	./proj3 -r sample-H.dmp -s > testH-s.out
	diff sample-A-s.out testA-s.out
	diff sample-B-s.out testB-s.out
	diff sample-C-s.out testC-s.out
	# TESTING ROUND TRIP TIMES
	./proj3 -r sample-A.dmp -t > testA-t.out
	./proj3 -r sample-B.dmp -t > testB-t.out
	./proj3 -r sample-C.dmp -t > testC-t.out
	./proj3 -r sample-D.dmp -t > testD-t.out
	./proj3 -r sample-E.dmp -t > testE-t.out
	./proj3 -r sample-F1.dmp -t > testF1-t.out
	./proj3 -r sample-F2.dmp -t > testF2-t.out
	./proj3 -r sample-F3.dmp -t > testF3-t.out
	./proj3 -r sample-H.dmp -t > testH-t.out
	diff sample-A-t.out testA-t.out
	diff sample-B-t.out testB-t.out
	diff sample-F1-t.out testF1-t.out
	diff sample-F2-t.out testF2-t.out
	diff sample-F3-t.out testF3-t.out
	diff sample-H-t.out testH-t.out

stress:
	gcc PacketTrace.c -g -o proj3
	./proj3 -r sample-I.dmp -p > testI-p.out
	./proj3 -r sample-I.dmp -s > testI-s.out
	./proj3 -r sample-I.dmp -t > testI-t.out
