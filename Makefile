# you might need to update some paths/options below, but probably not
PYTHON:=python3

SED:=sed
CP:=cp -f

ZIP:=zip
ZIPOPTIONS:=-u -r
ZIPIGNORES:=-x \*.DS_Store\* -x \*.gitkeep\*


############################
# DO NOT MODIFY BELOW HERE #
############################

####################
# packaging targets
#
.PHONY: zip package package-replication package-data zenodo
zip: package
package: package-replication package-data

package-replication:
	@$(CP) requirements.txt requirements.txt.save
	@$(SED) 's/>=/==/g' requirements.txt.save > requirements.txt
	-@$(ZIP) replication-pkg.zip $(ZIPOPTIONS) .env.example LICENSE Makefile README.md requirements.txt *.py *.sh llm-filtering/*.py llm-filtering/*.json llm-filtering/*.md sample.xlsx sample-judgments-human.csv $(ZIPIGNORES)
	@$(CP) requirements.txt.save requirements.txt
	@$(RM) requirements.txt.save

package-data:
	-@$(ZIP) data.zip $(ZIPOPTIONS) data cves cwes llm-filtering/data llm-filtering/responses $(ZIPIGNORES)

zenodo:
	$(PYTHON) bin/zenodo.py


################
# study targets
#
.PHONY: mine-prs cwes cves filter
mine-prs:
	${PYTHON} pr-miner.py --diffs --reviews --comments --timeline --commits
cwes:
	${PYTHON} cwe-miner.py
cves:
	${PYTHON} find-cves-in-prs.py
	${PYTHON} find-cwes-in-prs.py
filter:
	${PYTHON} move-dependabot.py
	${PYTHON} filter-prs.py

.PHONY: gen-sample
gen-sample:
	${PYTHON} generate-sample.py

.PHONY: top-cwes figure
top-cwes:
	${PYTHON} top-cwes.py
figure:
	${PYTHON} make-repo-figure.py


################
# clean targets
#
.PHONY: clean clean-zip clean-all

clean:
	${RM} -R __pycache__ bin/__pycache__ llm-filtering/__pycache__

clean-zip:
	${RM} replication-pkg.zip data.zip

clean-all: clean clean-zip
