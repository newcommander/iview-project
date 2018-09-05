<template>
    <div class="content-status-view">
        this is from Content Status, data is {{ data }}
        <div id="InterfaceBandwidth" style="width: 600px;height:250px;"></div>
    </div>
</template>
<script>
    export default {
        props: ['data'],
        data: function () {
            return {
                if_bw: null
            }
        },
        mounted: function () {
            let if_bw = this.$echarts.init(document.getElementById('InterfaceBandwidth'));
            this.if_bw = if_bw
            this.init_if_bw_chart()
        },
        methods: {
            init_if_bw_chart () {
                let option = {
                    animation: false,
                    tooltip: {
                        trigger: 'axis',
                        formatter: function (params) {
                            params = params[0];
                            return '' + params.value[1];
                        },
                        axisPointer: {
                            animation: false
                        }
                    },
                    xAxis: {
                        type: 'time',
                        splitLine: {
                            show: false
                        }
                    },
                    yAxis: {
                        name: 'MB/s',
                        type: 'value',
                        boundaryGap: [0, 0],
                        min: 0,
                        splitLine: {
                            show: false
                        }
                    },
                    legend: {
                        top: 20,
                        right: 20,
                        data: [
                            {name:'in', icon:'line'},
                            {name:'out', icon:'line'}
                        ]
                    },
                    series: [
                        {
                            name: 'in',
                            type: 'line',
                            showSymbol: false,
                            hoverAnimation: false,
                            smooth: true,
                            data: []
                        },
                        {
                            name: 'out',
                            type: 'line',
                            showSymbol: false,
                            hoverAnimation: false,
                            smooth: true,
                            data: []
                        }
                    ]
                }
                this.if_bw.setOption(option)
                setTimeout(() => { this.update_if_bw_chart() }, 10)
            },
            update_if_bw_chart () {
                let bw_in = []
                let bw_out = []
                this.$http.post('/supervisor', '{"type":"net_bw","length":300}').then(function (response) {
                    let t = new Date(response.data.start_time)
                    for (let i = 0; i < 300; i++) {
                        bw_in.push([t.toISOString(), response.data.recv[i]/1024/1024])
                        t.setSeconds(t.getSeconds() + 1)
                    }
                    t.setSeconds(t.getSeconds() - 300)
                    for (let i = 0; i < 300; i++) {
                        bw_out.push([t.toISOString(), response.data.send[i]/1024/1024])
                        t.setSeconds(t.getSeconds() + 1)
                    }
                    this.if_bw.setOption({
                        series: [
                            { data: bw_in },
                            { data: bw_out }
                        ]
                    })
                }, function (response) {
                    // something error.
                })
                setTimeout(() => { this.update_if_bw_chart() }, 1000)
            }
        }
    }
</script>
