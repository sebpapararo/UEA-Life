function profileUndisable( field ) {
  var input = document.getElementById(field);
  input.toggleAttribute('disabled');
  console.log(field);
}


$(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });