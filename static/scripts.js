function profileUndisable( field ) {
  var input = document.getElementById(field);
  var isDisabled = input.hasAttribute("disabled");
  console.log(isDisabled)
  input.toggleAttribute('disabled');
  // if the form is disabled enable it
  if(!isDisabled){

    var form = document.getElementById("update-" + field);
    form.submit();
  }
}


$(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });
