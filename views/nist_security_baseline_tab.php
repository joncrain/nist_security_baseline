<div id="nist_security_baseline-tab"></div>
<h2 data-i18n="nist_security_baseline.title"></h2>

<table id="nist_security_baseline-tab-table"></table>

<script>
$(document).on('appReady', function(){
    $.getJSON(appUrl + '/module/nist_security_baseline/get_data/' + serialNumber, function(data){
        var table = $('#nist_security_baseline-tab-table');
        $.each(data, function(key,val){
            var th = $('<th>').text(i18n.t('nist_security_baseline.column.' + key));
            var td = $('<td>').text(val);
            table.append($('<tr>').append(th, td));
        });
    });
});
</script>
