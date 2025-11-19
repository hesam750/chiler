define(['knockout', 'jquery'], function(ko, $) {
    function ComfortModalViewModel(params) {
        var self = this;

        self.setComfortTemperature = function() {
            var temp = $("#modal-comfort-temp").val();
            var deviceEngine = window.cFieldApp.deviceEngine;

            // IMPORTANT: Replace 'Comfort_SP' with the actual variable name from your PLC configuration.
            var varName = 'Comfort_SP';

            deviceEngine.writeVariable(varName, temp, function(res) {
                var alert = $("#modal-comfort-alert");
                if (res.status === 'success') {
                    alert.removeClass("alert-danger").addClass("alert-success");
                    alert.text("Comfort temperature set to " + temp);
                } else {
                    alert.removeClass("alert-success").addClass("alert-danger");
                    alert.text("Error setting comfort temperature: " + res.message);
                }
                alert.show();
                setTimeout(function() { alert.hide(); }, 5000);
            });
        };
    }

    ko.components.register('comfort-modal-component', {
        viewModel: ComfortModalViewModel,
        template: { require: 'text!view/component/comfort-modal.html' }
    });

    return ComfortModalViewModel;
});