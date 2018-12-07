<template>
    <div class="content-status-view">
        this is from Content Status, data is {{ data }}
        <div id="InterfaceBandwidth" style="width: 600px;height:250px;"></div>
        <Table stripe no-data-text="none" no-filtered-data-text="none" :columns="clients_list_header" :data="clients_list"></Table>
        <Table stripe no-data-text="none" no-filtered-data-text="none" :columns="if_list_header" :data="if_list"></Table>
        <Table stripe no-data-text="none" no-filtered-data-text="none" :columns="route_table_header" :data="route_table"></Table>
        <div id="Linklist" style="width: 600px;height:250px;"></div>
    </div>
</template>
<script>
    import expandRaw from './table_expand.vue';
    export default {
        components: { expandRaw },
        props: ['data'],
        data: function () {
            return {
                if_bw: null,
                if_list_header: [
                    {
                        type: 'expand',
                        width: 50,
                        render: (h, params) => {
                            return h(expandRaw, {
                                props: { row: params.row }
                            })
                        }
                    },
                    { title: 'Interface', key: 'name' },
                    { title: 'Address', key: 'addr' }
                ],
                if_list: [],
                clients_list_header: [
                    { title: 'Common name', key: 'cn' },
                    { title: 'Real address', key: 'real_addr' },
                    { title: 'Virtual address', key: 'virt_addr' },
                    { title: 'Bytes in', key: 'byte_recv' },
                    { title: 'Bytes out', key: 'byte_send' },
                    { title: 'Connected since', key: 'conn_since' },
                    { title: 'Last reference', key: 'last_ref' }
                ],
                clients_list: [],
                route_table_header: [
                    { title: 'Destination', key: 'dest' },
                    { title: 'Genmask', key: 'mask' },
                    { title: 'Gateway', key: 'gateway' },
                    { title: 'Interface', key: 'interface' }
                ],
                route_table: [],
                link_list: null
            }
        },
        mounted: function () {
            let if_bw = this.$echarts.init(document.getElementById('InterfaceBandwidth'));
            let link_list = this.$echarts.init(document.getElementById('Linklist'));
            this.if_bw = if_bw
            this.link_list = link_list
            this.init_if_bw_chart()
            this.update_clients_list()
            this.update_interface_list()
            this.update_route_table()
            this.init_link_list_chart()
        },
        methods: {
            is_object_empty(obj) {
                for (let key in obj) {
                    return false
                }
                return true
            },
            is_object_equal(obj1, obj2) {
                if (!this.is_object_empty(obj1)) {
                    for (let key in obj1) {
                        if (!(key in obj2))
                            return false
                        if (obj1[key] != obj2[key])
                            return false
                    }
                } else if (!this.is_object_empty(obj2)) {
                    for (let key in obj2) {
                        if (!(key in obj1))
                            return false
                        if (obj1[key] != obj2[key])
                            return false
                    }
                }
                return true
            },
            update_route_table() {
                this.$http.post('/supervisor', '{"type":"route_table"}').then(function (response) {
                    this.route_table = response.data
                }, function (response) {
                    // something error.
                    this.route_table = []
                })
                setTimeout(() => { this.update_route_table() }, 10000)
            },
            update_interface_list() {
                this.$http.post('/supervisor', '{"type":"ifconfig"}').then(function (response) {
                    if (this.if_list.length != response.data.length) {
                        this.if_list = response.data
                    } else {
                        for (let i = 0; i < response.data.length; i++) {
                            if (!(this.is_object_equal(this.if_list[i], response.data[i])))
                                this.if_list[i] = response.data[i]
                        }
                    }
                }, function (response) {
                    // something error.
                    this.if_list = []
                })
                setTimeout(() => { this.update_interface_list() }, 1000)
            },
            update_clients_list() {
                this.$http.post('/supervisor', '{"type":"clients_status"}').then(function (response) {
                    // TODO: response.data.statistics
                    if (this.is_object_empty(response.data.clients_list)) {
                        this.clients_list = []
                    } else {
                        let clients_list = []
                        for (let key in response.data.clients_list) {
                            clients_list.push(
                                {
                                    cn: response.data.clients_list[key]['common_name'],
                                    real_addr: response.data.clients_list[key]['real_addr'],
                                    virt_addr: response.data.clients_list[key]['virt_addr'],
                                    byte_recv: response.data.clients_list[key]['byte_recv'],
                                    byte_send: response.data.clients_list[key]['byte_send'],
                                    conn_since: response.data.clients_list[key]['conn_since'],
                                    last_ref: response.data.clients_list[key]['last_ref']
                                }
                            )
                        }
                        this.clients_list = clients_list
                    }
                }, function (response) {
                    // something error.
                    this.clients_list.length = 0
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
            },
            init_link_list_chart () {
                let option = {
                    animation: false,
                    title: {
                        text: "Link list",
                        x: "center"
                    },
                    tooltip: {
                        trigger: "axis",
                        axisPointer: {
                            type: "shadow",
                            areaStyle: {
                                color: "rgb(114, 182, 249)"
                            }
                        }
                    },
                    legend: {
                        data: ["in", "out"],
                        orient: "vertical",
                        x: "right"
                    },
                    toolbox: {
                        show: false
                    },
                    calculable: true,
                    xAxis: [
                        {
                            type: "value",
                            position: "top",
                            name: "KB/s",
                            nameLocation: "end",
                            nameTextStyle: {
                                fontWeight: "bolder"
                            },
                            min: 0,
                            axisLine: {
                                show: false
                            },
                            axisLabel: {
                                otate: 0,
                                show: true
                            },
                            splitNumber: 5,
                            axisTick: {
                                show: true,
                                lineStyle: {
                                    color: "rgb(186, 186, 186)"
                                }
                            },
                            splitLine: {
                                show: true,
                                lineStyle: {
                                    type: "dashed",
                                    color: "rgb(124, 124, 124)"
                                }
                            },
                            splitArea: {
                                show: false
                            }
                        }
                    ],
                    yAxis: [
                        {
                            type: "category",
                            data: [],
                            position: "left",
                            name: "Links",
                            nameLocation: "start",
                            nameTextStyle: {
                                color: "rgb(40, 40, 40)"
                            },
                            axisLine: {
                                show: true,
                                lineStyle: {
                                    color: "rgb(110, 179, 229)"
                                }
                            },
                            axisLabel: {
                                textStyle: {
                                    fontWeight: "bolder"
                                }
                            },
                            axisTick: {
                                show: false
                            },
                            splitArea: {
                                show: true
                            },
                            splitLine: {
                                show: false
                            }
                        }
                    ],
                    series: [
                        {
                            name: "in",
                            type: "bar",
                            barWidth: 7,
                            data: []
                        },
                        {
                            name: "out",
                            type: "bar",
                            barWidth: 7,
                            data: []
                        }
                    ],
                    grid: {
                        x: 119
                    }
                }
                this.link_list.setOption(option)
                setTimeout(() => { this.update_link_list_chart() }, 10)
            },
            update_link_list_chart () {
                let link_list = []
                let link_in = []
                let link_out = []
                let max = 0
                let max_x = 0
                let grid_height = 300
                this.$http.post('/ifmonitor', '{"if_name":"tun0","item":"link_list"}').then(function (response) {
                    grid_height = 20 * response.data.data.links.length
                    for (let i = response.data.data.links.length - 1; i >= 0; i--) {
                        let s_ip = response.data.data.links[i].s_ip
                        let d_ip = response.data.data.links[i].d_ip
                        let in_bytes = response.data.data.links[i].s2d_len
                        let out_bytes = response.data.data.links[i].d2s_len
                        link_list.push(s_ip + ' > ' + d_ip)
                        link_in.push((in_bytes / 1024).toFixed(2))
                        link_out.push((out_bytes / 1024).toFixed(2))
                        if ((in_bytes / 1024) > max)
                            max = in_bytes / 1024
                        if ((out_bytes / 1024) > max)
                            max = out_bytes / 1024
                    }
                    if (max < 40) {
                        max_x = 50
                    } else if (max < 80) {
                        max_x = 100
                    } else if (max < 400) {
                        max_x = 500
                    } else if (max < 800) {
                        max_x = 1000
                    } else if (max < 1600) {
                        max_x = 2000
                    } else {
                        max_x = 4000
                    }
                    this.link_list.setOption({
                        grid: {
                            height: grid_height
                        },
                        xAxis: [
                            { max: max_x }
                        ],
                        yAxis: [
                            { data: link_list }
                        ],
                        series: [
                            { data: link_in },
                            { data: link_out }
                        ]
                    })
                }, function (response) {
                    // something error.
                })
                setTimeout(() => { this.update_link_list_chart() }, 1000)
            }
        }
    }
</script>
