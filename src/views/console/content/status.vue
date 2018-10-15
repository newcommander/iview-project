<template>
    <div class="content-status-view">
        this is from Content Status, data is {{ data }}
        <div id="InterfaceBandwidth" style="width: 600px;height:250px;"></div>
        <Table stripe no-data-text="none" no-filtered-data-text="none" :columns="clients_list_header" :data="clients_list"></Table>
    </div>
</template>
<script>
    export default {
        props: ['data'],
        data: function () {
            return {
                if_bw: null,
                clients_list_header: [
                    { title: 'Common name', key: 'cn' },
                    { title: 'Real address', key: 'real_addr' },
                    { title: 'Virtual address', key: 'virt_addr' },
                    { title: 'Throughput in', key: 'byte_recv' },
                    { title: 'Throughput out', key: 'byte_send' },
                    { title: 'Connected since', key: 'conn_since' },
                    { title: 'Last reference', key: 'last_ref' }
                ],
                clients_list: []
            }
        },
        mounted: function () {
            let if_bw = this.$echarts.init(document.getElementById('InterfaceBandwidth'));
            this.if_bw = if_bw
            this.init_if_bw_chart()
            this.update_clients_list()
        },
        methods: {
            update_clients_list() {
                this.$http.post('/supervisor', '{"type":"clients_status"}').then(function (response) {
                    // response.data.statistics
                    this.clients_list.length = 0
                    for (var key in response.data.clients_list) {
                        console.log(key)
                        this.clients_list.push(
                            {
                                cn: response.data.clients_list[key]['common_name'],
                                real_addr: key,
                                virt_addr: response.data.clients_list[key]['virt_addr'],
                                byte_recv: response.data.clients_list[key]['byte_recv'],
                                byte_send: response.data.clients_list[key]['byte_send'],
                                conn_since: response.data.clients_list[key]['conn_since'],
                                last_ref: response.data.clients_list[key]['last_ref']
                            }
                        )
                    }
                }, function (response) {
                    // something error.
                })
                setTimeout(() => { this.update_clients_list() }, 1000)
            },
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
                        minInterval: 0.05,
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
                        bw_in.push([t.toISOString(), (response.data.recv[i]/1024/1024).toFixed(2)])
                        t.setSeconds(t.getSeconds() + 1)
                    }
                    t.setSeconds(t.getSeconds() - 300)
                    for (let i = 0; i < 300; i++) {
                        bw_out.push([t.toISOString(), (response.data.send[i]/1024/1024).toFixed(2)])
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
