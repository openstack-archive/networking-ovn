#!/bin/sh
# TODO(Reedip) remove --concurrency 0 once stestr is fixed
# preserve old behavior of using an arg as a regex when '--' is not present
case $@ in
  (*--*) ostestr --concurrency 0 $@;;
  ('') ostestr --concurrency 0;;
  (*) ostestr --concurrency 0 --regex "$@"
esac
