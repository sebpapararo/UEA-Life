function profileUndisable( field ) {
  var input = document.getElementById(field);
  var button = document.getElementById("button-" + field)
  var isDisabled = input.hasAttribute("disabled");

  input.toggleAttribute('disabled');
  // if the form is disabled enable it
  if(isDisabled){
    var form = document.getElementById("update-" + field);

  }else{
    form.submit();
  }
}


$(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });
