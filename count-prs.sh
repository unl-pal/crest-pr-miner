#!/bin/sh

echo "Repositories kept:"
find data -mindepth 2 -maxdepth 2 -type d > repo-count-kept.txt
cat repo-count-kept.txt | wc -l

echo "Repositories skipped:"
find skipped -mindepth 2 -maxdepth 2 -type d > repo-count-skipped.txt
cat repo-count-skipped.txt | wc -l

echo "Repositories total:"
cat repo-count-kept.txt repo-count-skipped.txt | sort | uniq | wc -l 

rm -f repo-count-kept.txt repo-count-skipped.txt

echo "PRs kept:"
kept=$(find data -maxdepth 4 -mindepth 4 -type f -name '[0-9]*.json'|wc -l)
echo $kept

echo "PRs skipped:"
skipped=$(find skipped -maxdepth 4 -mindepth 4 -type f -name '[0-9]*.json'|wc -l)
echo $skipped

echo "PRs total:"
total=$((kept + skipped))
echo $total
