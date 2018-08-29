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
                    title: { text: 'ECharts 入门示例' },
                    tooltip: {},
                    xAxis: {
                            data: ['衬衫', '羊毛衫', '雪纺衫', '裤子', '高跟鞋', '袜子']
                    },
                    yAxis: {},
                    series: [{
                        name: '销量',
                        type: 'bar',
                        data: [5, 20, 36, 10, 10, 20]
                    }]
                });
            }
        }
    }
</script>
