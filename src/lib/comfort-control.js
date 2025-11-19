define(['knockout', 'jquery'], function(ko, $) {
    function ComfortControlViewModel(params) {
        var self = this;

        self.IsAlertVisible = ko.observable(false);
        self.AlertCssClass = ko.observable("alert-success");
        self.AlertTitle1 = ko.observable("");

        self.closeAlert = function() {
            self.IsAlertVisible(false);
        };

        self.setComfortTemperature = function() {
            var temp = $("#comfort-temp").val();
            var deviceEngine = window.cFieldApp.deviceEngine;

            // Replace 'YOUR_VARIABLE_NAME' with the actual variable name for comfort temperature
            var varName = 'YOUR_VARIABLE_NAME'; 
            
            deviceEngine.writeVariable(varName, temp, function(res) {
                if (res.status === 'success') {
                    self.AlertCssClass("alert-success");
                    self.AlertTitle1("Comfort temperature set to " + temp);
                } else {
                    self.AlertCssClass("alert-danger");
                    self.AlertTitle1("Error setting comfort temperature: " + res.message);
                }
                self.IsAlertVisible(true);
            });
        };
    }

    ko.components.register('comfort-control-component', {
        viewModel: ComfortControlViewModel,
        template: { require: 'text!view/component/comfort-control.html' }
    });

    return ComfortControlViewModel;
});