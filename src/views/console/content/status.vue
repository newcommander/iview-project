<template>
    <div class="content-status-view">
        this is from Content Status, data is {{ data }}
        <div id="InterfaceBandwidth" style="width: 600px;height:400px;"></div>
    </div>
</template>
<script>
    export default {
        props: ['data'],
        mounted: function () {
            this.drawLine();
        },
        methods: {
            drawLine () {
                let ifbw = this.$echarts.init(document.getElementById('InterfaceBandwidth'));

                ifbw.setOption({
                    title: { text: 'Bandwidth' },
                    tooltip: {},
                    xAxis: {
                        data: ['text1', 'text2', 'text3', 'text4', 'text5', 'text6']
                    },
                    yAxis: {},
                    series: [{
                        name: 'bw',
                        type: 'line',
                        data: [5, 20, 36, 10, 10, 20]
                    }]
                });
            }
        }
    }
</script>
