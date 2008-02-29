PROGRAM = gressgraph

all : $(PROGRAM)

gressgraph : $(PROGRAM).lhs
	ghc -package parsec -fglasgow-exts -o $(PROGRAM) $<

pdf : $(PROGRAM).lhs
	lhs2TeX $< > $(PROGRAM).tex
	pdflatex $(PROGRAM).tex

sloc : $(PROGRAM).lhs
	lhs2TeX --code $< | grep --invert-match '^ *$$' | wc --lines
