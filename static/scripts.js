function profileUndisable( field ) {
  var input = document.getElementById(field);
  var button = document.getElementById("button-" + field)
  var isDisabled = input.hasAttribute("disabled");
  var form = document.getElementById("update-" + field);

  // if the form is disabled enable it
  if(isDisabled){
    input.toggleAttribute('disabled');
    button.classList.remove('btn-outline-secondary');
    button.classList.add('btn-success');
    button.innerHTML = "Submit Change";
  }else{
    form.submit();
  }
}


$(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });
