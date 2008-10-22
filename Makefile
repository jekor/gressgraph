PROGRAM = gressgraph
DIST := gressgraph-0.2

all : $(PROGRAM)

gressgraph : $(PROGRAM).lhs
	ghc -Wall -package parsec -fglasgow-exts -o $(PROGRAM) $<

doc : $(PROGRAM).lhs
	lhs2TeX $< > $(PROGRAM).tex
	pdflatex $(PROGRAM).tex

test : $(PROGRAM) test-iptables-output
	./$(PROGRAM) < test-iptables-output > test-graph.twopi
	twopi -Tsvg test-graph.twopi > test-graph.svg

sloc : $(PROGRAM).lhs
	lhs2TeX --code $< | grep --invert-match '^ *$$' | wc --lines

clean :
	rm $(PROGRAM).tex $(PROGRAM).aux $(PROGRAM).log $(PROGRAM).ptb
	rm $(PROGRAM).hi $(PROGRAM).o
	rm test-graph.twopi test-graph.svg

dist:
#	darcs dist would be nice, but we want to add gressgraph.pdf
	mkdir $(DIST)
	for f in `darcs query manifest`; do cp $$f $(DIST)/; done
#       append the documentation
	cp gressgraph.pdf $(DIST)/
	tar czvf $(DIST).tar.gz $(DIST)/
	rm -rf $(DIST)/
