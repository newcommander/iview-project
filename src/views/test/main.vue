<style scoped lang="less">
.layout{
    color: #fff;
    position: relative;
    overflow: auto;
}
</style>
<template>
    <div class="layout">
        <Layout>
            <Header :style="{position: 'fixed', width: '100%', padding: '0px 50px 0px 0px'}">
                <header_view :value=my_value></header_view>
            </Header>
            <Layout>
                <Sider width=64 :style="{position: 'fixed', height: '100%', top: '64px'}">
                    <sider_view></sider_view>
                </Sider>
                <Layout>
                    <Content :style="{margin: '88px 0 0 88px', background: '#fff', minHeight: '500px'}">
                        <content_view></content_view>
                    </Content>
                    <Footer class="layout-footer-center">
                        nihao
                    </Footer>
                </Layout>
            </Layout>
        </Layout>
    </div>
</template>
<script>
    import header_view from './header'
    import sider_view from './sider'
    import content_view from './content'
    import footer_view from './footer'

    export default {
        data: function () {
            return {
                my_value: "init_vv"
            }
        },
        components: {
            header_view,
            sider_view,
            content_view,
            footer_view
        },
        methods: {
        }
    }
</script>
