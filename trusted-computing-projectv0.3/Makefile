SUBDIRS = common
SUBDIRS += `ls */Makefile | sed "s/Makefile//g" | sed "s/common\///g"`

all:
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i ; done

install:
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install ; done

clean:
	@set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean ; done