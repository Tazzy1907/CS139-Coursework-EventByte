$(document).ready(function() {
    var events = $(".eventsList").children(); 
    events.hide();

    $(events).each(function(index) {
        $(this).delay(50 * index).fadeIn(1000);
    }); 
});