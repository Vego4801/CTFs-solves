#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, Response, session, render_template
from re import compile, escape, search
from random import choice, randint
from string import lowercase as ascii_lowercase
from functools import wraps
from os import environ

app = Flask(__name__)

# Return the value from SECRET_KEY or the string given in the second parameter
app.config['SECRET_KEY'] = environ.get('SECRET_KEY', 'eA2b8A2eA1EADa7b2eCbea7e3dAd1e')

def calc(recipe):
	global garage		# define a global variable inside local scope
	builtins, garage = {'__builtins__': None}, {}		# Assign empty set to garage and a "None" value to '__builtins__' inside the set

	#try:
	exec(recipe, builtins, garage)		# exec dynamically created programs which can also be strings!
	#except:		# comment to debug and see errors
	#	pass

def GFW(f):		# Great Firewall of the observable universe and it's infinite timelines  (decorator)
	@wraps(f)		# f is the function "index()" which is wrapped inside this decorators
	def federation(forbidden=['[', '(', '_', '.'], *a, **kw):
		ingredient = session.get('ingredient', None)	# retrieve the value inside 'ingredient' from the actual session
		measurements = session.get('measurements', None)	# same here for 'measurements'
		recipe = '%s = %s' % (ingredient, measurements)
  
		print(len(recipe))

		if ingredient and measurements and len(recipe) >= 20:
			regex = compile('|'.join(map(escape, sorted(forbidden, key=lambda f: -len(f)))))	# COMPILE return pattern object from regex
			matches = regex.findall(recipe)		# search for matches using the regex compiled

			if matches:		 # Here actually block the request
				return render_template('index.html', blacklisted='Morty you dumbass: ' + ', '.join(set(matches)))

			if len(recipe) > 305:	# Block execution of long code
				return f(*a, **kw)	# ionic defibulizer can't handle more bytes than that

			calc(recipe)
			#return render_template('index.html', calculations=garage[ingredient])
			return f(*a, **kw)	# rick deterrent	https://stackoverflow.com/questions/287085/what-do-args-and-kwargs-mean

		# generate a string with 10 random characters (JOIN add values in an iteable object togheter with the given string)
		ingredient = session['ingredient'] = ''.join(choice(ascii_lowercase) for _ in range(10))

		# generate a string which express an operation (MAP applies the given function for each element inside the iterable)
		measurements = session['measurements'] = ''.join(map(str, [randint(1, 69), choice(['+', '-', '*']), randint(1,69)]))
		calc('%s = %s' % (ingredient, measurements))
		return render_template('index.html', calculations=garage[ingredient])

	return federation

@app.route('/')
@GFW	# Wrap index() inside the decorator
def index():
	return render_template('index.html')

@app.route('/debug')
def debug():
	return Response(open(__file__).read(), mimetype='text/plain')

if True:#__name__ == '__main__':
	app.run('0.0.0.0', port=1337, debug=True)
