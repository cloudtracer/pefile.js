var gulp = require('gulp');
var pump = require('pump');

var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');

var browserify = require('browserify');
var watchify = require('watchify');
var concat = require('gulp-concat');
var notify = require("gulp-notify");
var transform = require('vinyl-transform');

function handleErrors() {
  var args = Array.prototype.slice.call(arguments);
  notify.onError({
    title: "Compile Error",
    message: "<%= error.trace %>"
  }).apply(this, args);
  this.emit('end'); // Keep gulp from hanging on this task
}

gulp.task('watch', function (cb) {
  // the same options as described above
  var watchFile = './pefile.js';
  gulp.watch(watchFile, ['watch']);

  return browserify([watchFile],{debug: true}).bundle().on('error', notify.onError({
      message: "Error: <%= error.message %> - <%= error %> ",
      title: "Browserify Failed"
    }))
    .pipe(source(watchFile))
    .pipe(buffer())
    .on('log', console.error)
    .pipe(gulp.dest('./gh-pages/js/'));
});

gulp.task('default', ['watch']);

//gulp.task('default', ['debug-watch-inject', 'debug-watch-background']);
