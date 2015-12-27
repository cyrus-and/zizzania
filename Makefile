.PHONY: release debug clean cleanall install uninstall

release:
	scons -C src/

debug:
	scons -C src/ debug=1

clean:
	scons -C src/ -c

cleanall: clean
	$(RM) src/.sconsign.dblite

install:
	install src/zizzania /usr/local/bin/

uninstall:
	$(RM) /usr/local/bin/zizzania
