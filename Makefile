APP=gressgraph
BIN=dist/build/$(APP)/$(APP)

all : $(BIN)

dist/setup-config : $(APP).cabal
	runhaskell Setup.hs configure

$(BIN) : dist/setup-config $(APP).lhs
	runhaskell Setup.hs build
	@touch $@ # cabal doesn't always update the build (if it doesn't need to)

.PHONY : doc test clean
doc : $(APP).lhs
	lhs2TeX $< > $(APP).tex
	pdflatex $(APP).tex

test : $(BIN) test-iptables-output
	$(BIN) < test-iptables-output > test-graph.twopi
	twopi -Tsvg test-graph.twopi > test-graph.svg

clean :
	-rm $(APP).tex $(APP).aux $(APP).log $(APP).ptb
	-rm -rf dist
	rm test-graph.twopi test-graph.svg
