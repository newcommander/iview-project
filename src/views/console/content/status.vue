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
                    xAxis: {
                        show: false,
                        type: 'category',
                        data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                    },
                    legend: {
                        top: 20,
                        right: 20,
                        orient: 'vertical',
                        data: ['in', 'out']
                    },
                    yAxis: {
                        type: 'value',
                        name: 'MB/s'
                    },
                    series: [
                        {
                            name: 'in',
                            data: [82, 93, 91, 93, 129, 133, 132],
                            type: 'line',
                            smooth: true
                        },
                        {
                            name: 'out',
                            data: [12, 93, 20, 93, 120, 130, 120],
                            type: 'line',
                            smooth: true
                        }
                    ]
                });
            }
        }
    }
</script>
