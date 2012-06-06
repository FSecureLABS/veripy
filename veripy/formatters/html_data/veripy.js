
Veripy = function() {

    var veripy = { Report: report };

    return veripy;

    function report(e) {
        
        var report = {  elem: e,
                        init: init }

        return report;

        function init() {
            console.log(report);
            // collapse all suites to show only the headers
            $('tbody tr.case', report.elem).hide();
            // add support for toggling the test suite detail
            $('tbody', report.elem).each(function() {
                var id = $('tr.suite th.title', this).text().toLowerCase().replace(/[^a-z0-9]+/g, "-");
                // convert each suite title into a link to toggle its detail
                $('tr.suite th.title', this).html('<a href="#' + id + '" id="' + id + '">' + $('tr.suite th.title', this).text() + '</a>');
                // attach an event handler to the new link, to perform the
                // toggling
                $('tr.suite th.title a', this).bind('click', { suite: $(this) }, toggle_suite); })

            // hide each test case description
            $('tbody tr.case th.title p.description', report.elem).hide();
            // add an on-hover handler that will show/hide the description of
            // a test case as you move between rows
            $('tbody tr.case', report.elem).hover(case_reveal_description, case_hide_description);
        }

        function case_hide_description() {
            $('th.title p.description', this).hide(); }

        function case_reveal_description() {
            $('th.title p.description', this).show(); }

        function toggle_suite(e) {
            if($('tr.case:visible', e.data.suite).length > 0) {
                $('tr.case', e.data.suite).hide();
            } else {
                $('tr.case', e.data.suite).show();
            }
        }
        
    }

}()


$(document).ready(function() {
  var report = Veripy.Report($('table#results'));

  report.init(); })
