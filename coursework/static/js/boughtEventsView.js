$(document).ready(function() {
    var events = $(".eventsList").children(); 
    events.hide();

    $(events).each(function(index) {
        $(this).delay(50 * index).fadeIn(1000);
    }); 
});


$('#upcoming').click(function() {
    $('#upcomingEvents').slideToggle("slow");
})

$('#cancelled').click(function() {
    $('#cancelledEvents').slideToggle("slow");
})

$('#completed').click(function() {
    $('#completedEvents').slideToggle("slow");
})