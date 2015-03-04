.PHONY: clean install uninstall install_testrig tox test coverage travis flake8 pypi docs web tag release
clean:
	find . -name "*.pyc" -delete

install:
	python setup.py install

uninstall:
	pip uninstall ldap3

pep8:
	py.test --pep8 -m pep8

test:
	pip install --user -r requirements.txt
	pip install --user -r requirements-dev.txt
	python -m tox

#tox:
#	pip install tox detox
#	detox

coverage:
	pip install coverage
	travis

travis:
	pip install coveralls
	coverage run --source=ldap3 runtests.py

pypi:
	python setup.py check --restructuredtext --strict
	python setup.py sdist upload
	#python2.6 setup.py bdist_wheel upload
	python2.7 setup.py bdist_wheel upload
	#python3.4 setup.py bdist_wheel upload

docs:
	pip install sphinx
	sphinx-build -b html docs/ docs/build/

tag:
	bumpversion minor
	git push origin master
	git push --tags

release:
	tag
	pypi
	web
