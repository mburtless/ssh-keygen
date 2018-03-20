var spawn = require('child_process').spawn;
var _ = require('underscore');
var fs = require('fs');
var os = require('os');
var path = require('path');

var log = function(a){
	if(process.env.VERBOSE) console.log('ssh-keygen: '+a);
}
function binPath() {
	if(process.platform !== 'win32') return 'ssh-keygen';

	switch(process.arch) {
		case 'ia32': return path.join(__dirname, '..', 'bin', 'ssh-keygen-32.exe');
		case 'x64': return path.join(__dirname, '..', 'bin', 'ssh-keygen-64.exe');
	}

	throw new Error('Unsupported platform');
}
function checkAvailability(location, force, callback){
	var pubLocation = location+'.pub';
	log('checking availability: '+location);
	fs.exists(location, function(keyExists){
		log('checking availability: '+pubLocation);
		fs.exists(pubLocation, function(pubKeyExists){
			doForce(keyExists, pubKeyExists);
		})
	});
	function doForce(keyExists, pubKeyExists){
		if(!force && keyExists) return callback(location+' already exists');
		if(!force && pubKeyExists) return callback(pubLocation+' already exists');
		if(!keyExists && !pubKeyExists) return callback();
		if(keyExists){
			log('removing '+location);
			fs.unlink(location, function(err){
				if(err) return callback(err);
				keyExists = false;
				if(!keyExists && !pubKeyExists) callback();
			});
		}
		if(pubKeyExists) {
			log('removing '+pubLocation);
			fs.unlink(pubLocation, function(err){
				if(err) return callback(err);
				pubKeyExists = false;
				if(!keyExists && !pubKeyExists) callback();
			});
		}
	}
}
function ssh_keysign(opts, callback){
	var location = path.dirname(opts.publickey) + "/" + path.basename(opts.publickey, '.pub') + '-cert.pub'
	opts || (opts={});

	if(!opts.comment) opts.comment = '';
	
	//Initial set of options for sshkeygen
	var spawnOpts = [
		'-s', opts.cakey,
		'-C', opts.comment
	];
	// Push optional options if defined
	if(opts.hostKey){
		spawnOpts.push('-h');
	}
	if(opts.principal){
		spawnOpts.push('-n', opts.principal);
	}
	if(opts.validity){
		spawnOpts.push('-V', opts.validity);
	}
	if(opts.identity){
		spawnOpts.push('-I', opts.identity);
	}
	spawnOpts.push(opts.publickey);
	var keygen = spawn(binPath(), spawnOpts);

	keygen.stdout.on('data', function(a){
		log('stdout:'+a);
	});

	var read = opts.read;
	var destroy = opts.destroy;

	keygen.on('exit',function(){
		log('exited');
		if(read){
			log('reading cert '+location);
			fs.readFile(location, 'utf8', function(err, key){
				if(destroy){
					log('destroying cert '+location);
					fs.unlink(location, function(err){
						if(err) return callback(err);
					});
				}
				callback(undefined, { key: key });
			});
		} else if(callback) callback();
	});

	keygen.stderr.on('data',function(a){
		log('stderr:'+a);
	});

}
function ssh_keygen(location, opts, callback){
	opts || (opts={});

	var pubLocation = location+'.pub';
	if(!opts.comment) opts.comment = '';
	if(!opts.password) opts.password = '';
	if(!opts.size) opts.size = '2048';

	var keygen = spawn(binPath(), [
		'-t','rsa',
		'-b', opts.size,
		'-C', opts.comment,
		'-N', opts.password,
		'-f', location
	]);

	keygen.stdout.on('data', function(a){
		log('stdout:'+a);
	});

	var read = opts.read;
	var destroy = opts.destroy;

	keygen.on('exit',function(){
		log('exited');
		if(read){
			log('reading key '+location);
			fs.readFile(location, 'utf8', function(err, key){
				if(destroy){
					log('destroying key '+location);
					fs.unlink(location, function(err){
						if(err) return callback(err);
						readPubKey();
					});
				} else readPubKey();
				function readPubKey(){
					log('reading pub key '+pubLocation);
					fs.readFile(pubLocation, 'utf8', function(err, pubKey){
						if(destroy){
							log('destroying pub key '+pubLocation);
							fs.unlink(pubLocation, function(err){
								if(err) return callback(err);
								key = key.toString();
								key = key.substring(0, key.lastIndexOf(" \n"));
								pubKey = pubKey.toString();
								pubKey = pubKey.substring(0, pubKey.lastIndexOf(" \n"));
								return callback(undefined, {
									key: key, pubKey: pubKey
								});
							});
						} else callback(undefined, { key: key, pubKey: pubKey });
					});
				}
			});
		} else if(callback) callback();
	});

	keygen.stderr.on('data',function(a){
		log('stderr:'+a);
	});
};

function checkFileExists(file) {
	return new Promise((resolve, reject) => {
		fs.stat(file, (err, stats) => {
			if(err){
				if(err.code == 'ENOENT') resolve(false);
				else reject(err);
			}
			else resolve(stats.isFile());
		});
	});
}

module.exports = function(opts, callback){
	var location = opts.location;
	if(!location) location = path.join(os.tmpdir(),'id_rsa');

	if(_.isUndefined(opts.read)) opts.read = true;
	if(_.isUndefined(opts.force)) opts.force = true;
	if(_.isUndefined(opts.destroy)) opts.destroy = false;
	
	if(opts.sign && opts.cakey && opts.publickey && opts.identity) {
		log('signing mode set, ignoring location and password parameters');
		//verify cakey and publickey exist
		opsCounter = 0;
		keyFiles = [opts.cakey, opts.publickey]
		keyFiles.forEach((file) => {
			checkFileExists(file).then((isFile) => {
				if(!isFile) {
					var errMsg = file + " does not exist or is not accessible"
					return callback(new Error(errMsg));
				}
				opsCounter++;
				if(opsCounter == keyFiles.length) {
					ssh_keysign(opts, callback);
				}
			}).catch((err) => {
				console.log(err);
				var errMsg = file + " does not exist or is not accessible"
				return callback(new Error(errMsg));
			});
		});
		//call ssh_keysign
	} else if(opts.sign && _.isUndefined(opts.cakey)) {
		log('CA Key must be be defined when in signing mode');
	} else if(opts.sign && _.isUndefined(opts.publickey)) {
		log('Public key must be defined when in signing mode');
	} else if(opts.sign && _isUndefined(opts.identity)) {
		log('Identity must be defined when in signing mode');
	} else {
		checkAvailability(location, opts.force, function(err){
			if(err){
				log('availability err '+err);
				return callback(err);
			}
			ssh_keygen(location, opts, callback);
		});
	}	
};
